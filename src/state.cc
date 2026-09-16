// entity-ledger · src/state.cc —— 引擎状态与反向接口出口（P8/P9）
//
// 权威依据：
//   · protocol.md §6 反向接口命名 / §3.3 幂等与冲突 / §4.1 CTR-EV-06（同一次广播同一 ts）
//   · 需求专篇 ELG-NFR-02（出口全走注入的反向接口）、ELG-NFR-03（确定性、时间可注入）、
//     ELG-NFR-01（零外部依赖）
//
// 写前提交：任何改变台账的操作 MUST 先 `store->save()` 成功，再改内存（失败 → 1005 且状态不变）。
#include "internal.h"

#include <chrono>
#include <cstdio>
#include <fstream>

namespace entity_ledger {

// ============================================================================
// 内置系统时钟（未注入 IClock 时的唯一非确定性来源）
// ============================================================================

int64_t SystemClock::nowMs() const {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

namespace detail {

bool State::tryAcquire(const std::string& key) {
    std::lock_guard<std::mutex> lk(busyMtx);
    if (busy.count(key)) return false;
    busy.insert(key);
    return true;
}

void State::release(const std::string& key) {
    std::lock_guard<std::mutex> lk(busyMtx);
    busy.erase(key);
}

int64_t State::nowLocked() const {
    if (clock) return clock->nowMs();
    if (systemClock) return systemClock->nowMs();
    return 0;
}

MissionState* State::findMissionLocked(const std::string& missionId) {
    auto it = missions.find(missionId);
    return it == missions.end() ? nullptr : &it->second;
}

MissionState& State::missionLocked(const std::string& missionId) {
    auto it = missions.find(missionId);
    if (it != missions.end()) return it->second;
    MissionState fresh;
    fresh.missionId = missionId;
    if (store) {
        json loaded;
        bool ok = false;
        try {
            ok = store->load(missionId, loaded);
        } catch (...) {
            ++metrics.storeErrors;
            ok = false;
        }
        if (ok) {
            MissionState parsed;
            if (missionFromJson(loaded, parsed)) {
                parsed.missionId = missionId;
                fresh = std::move(parsed);
            }
        }
    }
    auto res = missions.emplace(missionId, std::move(fresh));
    return res.first->second;
}

void State::ensureStoreLoadedLocked() {
    if (!store || storeLoaded) return;
    storeLoaded = true;
    if (!store->supportsList()) return;  // 不支持列举：只能按 missionId 逐个懒加载
    std::vector<std::string> ids;
    try {
        ids = store->listMissionIds();
    } catch (...) {
        ++metrics.storeErrors;
        return;
    }
    for (const auto& id : ids) {
        if (missions.count(id)) continue;
        json loaded;
        bool ok = false;
        try {
            ok = store->load(id, loaded);
        } catch (...) {
            ++metrics.storeErrors;
            ok = false;
        }
        if (!ok) continue;
        MissionState parsed;
        if (missionFromJson(loaded, parsed)) {
            parsed.missionId = id;
            missions.emplace(id, std::move(parsed));
        }
    }
}

bool State::persistLocked(const MissionState& m) {
    if (!store) return true;
    const json snapshot = missionToJson(m);
    try {
        if (!store->save(m.missionId, snapshot)) {
            ++metrics.storeErrors;
            return false;
        }
    } catch (...) {
        ++metrics.storeErrors;
        return false;
    }
    return true;
}

void State::emitEntityChanged(const std::string& missionId, const EntityRecord& rec,
                              const std::string& change, const std::string& detail, int64_t ts) {
    if (!sink) return;
    EntityChangeEvent e;
    e.entityId = rec.id;
    e.no = rec.no;
    e.missionId = missionId;
    e.change = change;
    e.detail = detail;
    e.ts = ts;
    try {
        sink->onEntityChanged(e);
    } catch (...) {
        ++metrics.sinkErrors;
    }
}

void State::emitTargetState(const EntityRecord& rec, int64_t ts) {
    if (!sink) return;
    TargetStateEvent e;
    e.targetId = rec.id;
    e.targetNo = rec.no;
    e.threat = rec.threatBand;
    e.confidence = rec.confidence;
    e.dynamicState = rec.dynamicState;
    e.lng = rec.lng;
    e.lat = rec.lat;
    e.status = rec.status;
    e.ts = ts;
    try {
        sink->onTargetState(e);
    } catch (...) {
        ++metrics.sinkErrors;
    }
}

void State::audit(const AuditEntry& e) {
    if (!log) return;
    try {
        log->commandAudit(e);
    } catch (...) {
        ++metrics.sinkErrors;
    }
}

void State::logEvent(int level, const std::string& event, const json& data) {
    if (!log) return;
    try {
        log->log(level, event, data);
    } catch (...) {
        ++metrics.sinkErrors;
    }
}

void decorateEntity(const State& st, const MissionState& m, EntityRecord& rec) {
    rec.typeName = st.def.typeName(rec.typeKey);
    rec.sourceCount = static_cast<int>(rec.sources.size());
    rec.multiSource = rec.sources.size() > 1;
    rec.relations.clear();
    for (const auto& e : m.relations) {
        if (e.fromId == rec.id) {
            EntityLink l;
            l.kind = e.kind;
            l.state = e.state;
            l.toId = e.toId;
            l.toNo = e.toNo;
            l.outgoing = true;
            rec.relations.push_back(l);
        } else if (e.toId == rec.id) {
            EntityLink l;
            l.kind = e.kind;
            l.state = e.state;
            l.toId = e.fromId;
            l.toNo = e.fromNo;
            l.outgoing = false;
            rec.relations.push_back(l);
        }
    }
}

}  // namespace detail

// ============================================================================
// 自由函数
// ============================================================================

const char* errorCodeName(int code) {
    switch (code) {
        case 0: return "ok";
        case 1000: return "bad-request";
        case 1002: return "conflict";
        case 1003: return "gate-unmet";
        case 1004: return "not-found";
        case 1005: return "internal";
        case 1006: return "version-mismatch";
        default: return "unknown";
    }
}

std::string policiesDigest(const json& pkg) { return detail::fnv1a64Hex(detail::canonicalBytes(pkg)); }

}  // namespace entity_ledger
