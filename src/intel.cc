// entity-ledger · src/intel.cc —— 情报关联（ELG-INTEL）
//
// 权威依据：
//   · ELG-INTEL-01 关系链：有向关系可增删查；**成环 MUST 被检出**（风险 R6：查询死循环）
//   · ELG-INTEL-02 关联查询：上下游链路 + "关联目标数"（第三屏统计项）
//   · ELG-INTEL-03 已确认 / 疑似两态（confirmed / suspected 取值由规则声明）可筛选、可统计
//
// 成环处理的两层保障：
//   ① 写入侧：规则声明 `cyclic=false` 的关系种类成环 → **拒绝**（1003 + `$acyclic` + 成环路径）；
//      声明 `cyclic=true`（如对等协同）的关系允许成环，但查询仍 MUST 终止。
//   ② 查询侧：`chain()` 一律用已访问集合 + 深度上限，任何环都不可能造成死循环。
//      `detectCycles()` 可对已存在的图做全量检出（含 cyclic=true 的环），用于审计与演示。
#include "internal.h"

#include <algorithm>

namespace entity_ledger {

namespace {

using detail::MissionState;
using detail::State;

const RelationDef* findKind(const detail::Definition& def, const std::string& kind) {
    for (const auto& k : def.relations.kinds) {
        if (k.key == kind) return &k;
    }
    return nullptr;
}

bool stateDeclared(const detail::Definition& def, const std::string& s) {
    for (const auto& k : def.relations.states) {
        if (k.key == s) return true;
    }
    return false;
}

/// 在 `kind` 的关系子图上做 DFS：`from` 沿 fromId→toId 是否可达 `target`
bool reachable(const std::vector<RelationEdge>& edges, const std::string& kind,
               const std::string& from, const std::string& target,
               std::vector<std::string>* path) {
    std::vector<std::string> stack;
    std::set<std::string> visited;
    stack.push_back(from);
    std::vector<std::string> trail;
    // 迭代式 DFS（确定性：按 edges 声明顺序展开）
    std::function<bool(const std::string&)> dfs = [&](const std::string& cur) -> bool {
        if (cur == target) {
            trail.push_back(cur);
            if (path) *path = trail;
            trail.pop_back();
            return true;
        }
        if (visited.count(cur)) return false;
        visited.insert(cur);
        trail.push_back(cur);
        for (const auto& e : edges) {
            if (e.kind != kind) continue;
            if (e.fromId != cur) continue;
            if (dfs(e.toId)) {
                trail.pop_back();
                return true;
            }
        }
        trail.pop_back();
        return false;
    };
    return dfs(from);
}

}  // namespace

RelationResult EntityLedger::addRelation(const RelationInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RelationResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (in.missionId.empty() || in.fromId.empty() || in.toId.empty()) {
        res.code = 1000;
        res.message = "missionId, fromId and toId are required";
        return res;
    }
    if (in.fromId == in.toId) {
        res.code = 1000;
        res.message = "self relation is not allowed";
        return res;
    }
    const std::string kind = in.kind.empty() ? (st.def.relations.kinds.empty()
                                                    ? std::string()
                                                    : st.def.relations.kinds.front().key)
                                             : in.kind;
    const RelationDef* kd = findKind(st.def, kind);
    if (!kd) {
        res.code = 1000;
        res.message = "unknown relation kind: " + kind;
        return res;
    }
    std::string stateKey = in.state.empty() ? st.def.relations.defaultState : in.state;
    if (stateKey.empty()) {
        res.code = 1000;
        res.message = "relation state is required (rules declare no default)";
        return res;
    }
    if (!stateDeclared(st.def, stateKey)) {
        res.code = 1000;
        res.message = "unknown relation state: " + stateKey;
        return res;
    }
    auto mit = st.missions.find(in.missionId);
    if (mit == st.missions.end()) {
        res.code = 1004;
        res.message = "mission not found";
        return res;
    }
    MissionState& m = mit->second;
    auto fromIt = m.entities.find(in.fromId);
    auto toIt = m.entities.find(in.toId);
    if (fromIt == m.entities.end() || toIt == m.entities.end()) {
        // protocol.md §2.3：写入引用不存在的 id MUST 拒绝并可读
        res.code = 1004;
        res.message = "entity not found";
        return res;
    }
    for (const auto& e : m.relations) {
        if (e.fromId == in.fromId && e.toId == in.toId && e.kind == kind) {
            res.code = 0;
            res.message = "relation already exists";
            res.status = "already-exists";
            res.idempotent = true;
            res.edge = e;
            return res;
        }
    }
    // 成环检出（R6）
    if (!kd->cyclic) {
        std::vector<std::string> path;
        if (reachable(m.relations, kind, in.toId, in.fromId, &path)) {
            ++st.metrics.relationsRejected;
            ++st.metrics.cycleRejected;
            res.code = 1003;
            res.message = "relation would create a cycle";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$acyclic", "cycle detected in a non-cyclic relation kind",
                                          kind});
            res.cycle.push_back(in.fromId);
            for (const auto& p : path) res.cycle.push_back(p);
            return res;
        }
    }
    MissionState backup = m;
    RelationEdge edge;
    edge.missionId = in.missionId;
    edge.kind = kind;
    edge.state = stateKey;
    edge.fromId = in.fromId;
    edge.fromNo = fromIt->second.no;
    edge.toId = in.toId;
    edge.toNo = toIt->second.no;
    edge.at = now;
    edge.operatorId = in.operatorId;
    m.relations.push_back(edge);
    if (!st.persistLocked(m)) {
        m = std::move(backup);
        res.code = 1005;
        res.message = "store save failed";
        return res;
    }
    ++st.metrics.relationsAdded;
    res.code = 0;
    res.message = "added";
    res.status = "added";
    res.edge = edge;
    st.emitEntityChanged(in.missionId, fromIt->second, "relation-add", kind, now);
    return res;
}

RelationResult EntityLedger::removeRelation(const RelationInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RelationResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    auto mit = st.missions.find(in.missionId);
    if (mit == st.missions.end()) {
        res.code = 1004;
        res.message = "mission not found";
        return res;
    }
    MissionState& m = mit->second;
    for (std::size_t i = 0; i < m.relations.size(); ++i) {
        const RelationEdge& e = m.relations[i];
        if (e.fromId != in.fromId || e.toId != in.toId) continue;
        if (!in.kind.empty() && e.kind != in.kind) continue;
        MissionState backup = m;
        res.edge = e;
        m.relations.erase(m.relations.begin() + static_cast<long>(i));
        if (!st.persistLocked(m)) {
            m = std::move(backup);
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        res.code = 0;
        res.message = "removed";
        res.status = "removed";
        return res;
    }
    res.code = 0;
    res.message = "relation not found";
    res.status = "not-found";
    res.idempotent = true;  // 幂等：重复移出不报错
    return res;
}

std::vector<RelationEdge> EntityLedger::relations(const RelationQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<RelationEdge> out;
    auto mit = st.missions.find(q.missionId);
    if (mit == st.missions.end()) return out;
    const std::string dir = q.direction.empty() ? std::string("both") : q.direction;
    for (const auto& e : mit->second.relations) {
        if (!q.kind.empty() && e.kind != q.kind) continue;
        if (!q.state.empty() && e.state != q.state) continue;
        if (!q.entityId.empty()) {
            const bool isFrom = (e.fromId == q.entityId);
            const bool isTo = (e.toId == q.entityId);
            if (dir == "out" && !isFrom) continue;
            if (dir == "in" && !isTo) continue;
            if (dir == "both" && !isFrom && !isTo) continue;
        }
        out.push_back(e);
    }
    if (q.offset > 0) {
        if (static_cast<std::size_t>(q.offset) >= out.size()) return {};
        out.erase(out.begin(), out.begin() + q.offset);
    }
    if (q.limit > 0 && static_cast<std::size_t>(q.limit) < out.size()) {
        out.resize(static_cast<std::size_t>(q.limit));
    }
    return out;
}

ChainResult EntityLedger::chain(const ChainQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ChainResult res;
    res.entityId = q.entityId;
    res.depthLimit = q.depthLimit;
    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(q.entityId);
        if (eit == kv.second.entities.end()) continue;
        const MissionState& m = kv.second;
        res.no = eit->second.no;

        const auto allowed = [&](const RelationEdge& e) {
            if (!q.kind.empty() && e.kind != q.kind) return false;
            if (!q.includeSuspected && e.state == "suspected") return false;
            return true;
        };
        // 下游：沿 fromId→toId 广度优先；已访问集合保证终止（ELG-INTEL-01 / R6）
        std::set<std::string> visited;
        visited.insert(q.entityId);
        std::vector<std::pair<std::string, int>> frontier;
        frontier.emplace_back(q.entityId, 0);
        while (!frontier.empty()) {
            const auto cur = frontier.front();
            frontier.erase(frontier.begin());
            if (cur.second >= q.depthLimit) {
                res.truncated = true;
                continue;
            }
            for (const auto& e : m.relations) {
                if (e.fromId != cur.first || !allowed(e)) continue;
                ChainNode n;
                n.id = e.toId;
                auto nit = m.entities.find(e.toId);
                n.no = nit == m.entities.end() ? e.toNo : nit->second.no;
                n.typeKey = nit == m.entities.end() ? std::string() : nit->second.typeKey;
                n.depth = cur.second + 1;
                n.viaKind = e.kind;
                n.viaState = e.state;
                if (visited.count(e.toId)) {
                    res.cycleDetected = true;  // 已访问 → 图中存在环（查询仍终止）
                    continue;
                }
                visited.insert(e.toId);
                res.downstream.push_back(n);
                frontier.emplace_back(e.toId, cur.second + 1);
            }
        }
        // 上游：沿 toId→fromId
        std::set<std::string> upVisited;
        upVisited.insert(q.entityId);
        std::vector<std::pair<std::string, int>> upFrontier;
        upFrontier.emplace_back(q.entityId, 0);
        while (!upFrontier.empty()) {
            const auto cur = upFrontier.front();
            upFrontier.erase(upFrontier.begin());
            if (cur.second >= q.depthLimit) {
                res.truncated = true;
                continue;
            }
            for (const auto& e : m.relations) {
                if (e.toId != cur.first || !allowed(e)) continue;
                ChainNode n;
                n.id = e.fromId;
                auto nit = m.entities.find(e.fromId);
                n.no = nit == m.entities.end() ? e.fromNo : nit->second.no;
                n.typeKey = nit == m.entities.end() ? std::string() : nit->second.typeKey;
                n.depth = cur.second + 1;
                n.viaKind = e.kind;
                n.viaState = e.state;
                if (upVisited.count(e.fromId)) {
                    res.cycleDetected = true;
                    continue;
                }
                upVisited.insert(e.fromId);
                res.upstream.push_back(n);
                upFrontier.emplace_back(e.fromId, cur.second + 1);
            }
        }
        std::set<std::string> related;
        for (const auto& n : res.downstream) related.insert(n.id);
        for (const auto& n : res.upstream) related.insert(n.id);
        res.relatedCount = static_cast<int>(related.size());  // "关联目标数"（去重）
        res.cycles = detectCycles(kv.first);
        res.code = 0;
        res.message = "ok";
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

std::vector<CyclePath> EntityLedger::detectCycles(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<CyclePath> out;
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return out;
    const MissionState& m = mit->second;

    // 按 kind 分组，逐种类做 DFS 找环（确定性：种类与边均按声明顺序）
    std::vector<std::string> kinds;
    for (const auto& e : m.relations) {
        if (std::find(kinds.begin(), kinds.end(), e.kind) == kinds.end()) kinds.push_back(e.kind);
    }
    for (const auto& kind : kinds) {
        std::set<std::string> nodes;
        for (const auto& e : m.relations) {
            if (e.kind != kind) continue;
            nodes.insert(e.fromId);
            nodes.insert(e.toId);
        }
        std::map<std::string, int> color;  // 0 未访问 / 1 在栈 / 2 已完成
        std::vector<std::string> trail;
        std::set<std::string> reported;
        std::function<void(const std::string&)> dfs = [&](const std::string& cur) {
            color[cur] = 1;
            trail.push_back(cur);
            for (const auto& e : m.relations) {
                if (e.kind != kind || e.fromId != cur) continue;
                const std::string& nxt = e.toId;
                if (color[nxt] == 1) {
                    // 找到环：从 trail 中 nxt 首次出现处截取
                    auto it = std::find(trail.begin(), trail.end(), nxt);
                    if (it != trail.end()) {
                        CyclePath cp;
                        cp.missionId = missionId;
                        for (auto k = it; k != trail.end(); ++k) {
                            cp.ids.push_back(*k);
                            auto nit = m.entities.find(*k);
                            cp.nos.push_back(nit == m.entities.end() ? 0 : nit->second.no);
                            cp.kinds.push_back(kind);
                        }
                        cp.ids.push_back(nxt);
                        auto nit = m.entities.find(nxt);
                        cp.nos.push_back(nit == m.entities.end() ? 0 : nit->second.no);
                        cp.kinds.push_back(kind);
                        std::string key;
                        for (const auto& x : cp.ids) key += x + "|";
                        if (!reported.count(key)) {
                            reported.insert(key);
                            out.push_back(cp);
                        }
                    }
                } else if (color[nxt] != 1) {
                    dfs(nxt);
                }
            }
            trail.pop_back();
            color[cur] = 2;
        };
        for (const auto& n : nodes) {
            if (color[n] == 0) dfs(n);
        }
    }
    return out;
}

RelationStats EntityLedger::relationStats(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RelationStats out;
    out.missionId = missionId;
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return out;
    const MissionState& m = mit->second;
    out.edges = static_cast<int>(m.relations.size());
    std::map<std::string, int> byKind;
    std::map<std::string, int> byState;
    std::set<std::string> withRel;
    for (const auto& e : m.relations) {
        byKind[e.kind] += 1;
        byState[e.state] += 1;
        withRel.insert(e.fromId);
        withRel.insert(e.toId);
    }
    for (const auto& kv : byKind) out.byKind.push_back(RelationStatItem{kv.first, kv.second});
    for (const auto& kv : byState) out.byState.push_back(RelationStatItem{kv.first, kv.second});
    out.entitiesWithRelations = static_cast<int>(withRel.size());
    int isolated = 0;
    for (const auto& id : m.order) {
        if (!withRel.count(id)) ++isolated;
    }
    out.isolatedEntities = isolated;
    return out;
}

}  // namespace entity_ledger
