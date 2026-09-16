// entity-ledger · src/serialize.cc —— 公开类型的 JSON 序列化（camelCase；键序 = 成员声明顺序）
//
// 约束：
//   · protocol.md P4：对外字段命名 MUST 为 camelCase
//   · protocol.md §3.1：统一信封 {code, message, data}；code=0 为唯一成功码
//   · protocol.md §3.3 CTR-EC-01：幂等命中 code=0 + data.idempotent=true
//   · protocol.md §4.4：`target.state` 负载为既有冻结形状，字段只增不改（CTR-EV-04）
//   · protocol.md §4.4：`entity.consistency` 的 diffs 元素键序为 {no, field, views[]}
#include "internal.h"

#include <cstdio>

namespace entity_ledger {

namespace {

json envelope(int code, const std::string& message, const json& data) {
    json out = json::object();
    out["code"] = code;
    out["message"] = message;
    out["data"] = data;
    return out;
}

/// 0..1 的小数保留 6 位（确定性：同输入同输出；MUST NOT 出现浮点噪声）
double q6(double v) {
    const double scaled = v * 1000000.0;
    const double rounded = scaled >= 0 ? (scaled + 0.5) : (scaled - 0.5);
    return static_cast<double>(static_cast<long long>(rounded)) / 1000000.0;
}

}  // namespace

// ---------------------------------------------------------------- 基础

json toJson(const EntityRef& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    return j;
}

json toJson(const PhaseContext& v) {
    json j = json::object();
    j["phaseKey"] = v.phaseKey;
    j["seq"] = v.seq;
    j["scenarioKey"] = v.scenarioKey;
    j["enteredAt"] = v.enteredAt;
    j["missionId"] = v.missionId;
    return j;
}

json toJson(const LoadIssue& v) {
    json j = json::object();
    j["path"] = v.path;
    j["field"] = v.field;
    j["reason"] = v.reason;
    return j;
}

json toJson(const DefinitionInfo& v) {
    json j = json::object();
    j["loaded"] = v.loaded;
    j["policiesNamespace"] = v.policiesNamespace;
    j["schemaVersion"] = v.schemaVersion;
    j["definitionVersion"] = v.definitionVersion;
    j["digest"] = v.digest;
    j["policiesMajor"] = v.policiesMajor;
    j["entityTypeCount"] = v.entityTypeCount;
    j["actionCount"] = v.actionCount;
    j["viewCount"] = v.viewCount;
    j["factorCount"] = v.factorCount;
    j["bandCount"] = v.bandCount;
    j["flagCount"] = v.flagCount;
    j["relationKindCount"] = v.relationKindCount;
    j["dynamicStateCount"] = v.dynamicStateCount;
    json tk = json::array();
    for (const auto& s : v.entityTypeKeys) tk.push_back(s);
    j["entityTypeKeys"] = tk;
    json ak = json::array();
    for (const auto& s : v.actionKeys) ak.push_back(s);
    j["actionKeys"] = ak;
    json vk = json::array();
    for (const auto& s : v.viewKeys) vk.push_back(s);
    j["viewKeys"] = vk;
    json bk = json::array();
    for (const auto& s : v.bandKeys) bk.push_back(s);
    j["bandKeys"] = bk;
    json wn = json::array();
    for (const auto& s : v.warnings) wn.push_back(s);
    j["warnings"] = wn;
    return j;
}

json LoadResult::toJson() const { return envelope(code, message, entity_ledger::toJson(data)); }

// ---------------------------------------------------------------- 实体台账

json toJson(const EntityType& v) {
    json j = json::object();
    j["key"] = v.key;
    j["name"] = v.name;
    j["baseThreat"] = q6(v.baseThreat);
    j["attributes"] = v.attributes;
    return j;
}

json toJson(const SourceObs& v) {
    json j = json::object();
    j["source"] = v.source;
    j["obsKey"] = v.obsKey;
    j["confidence"] = q6(v.confidence);
    j["at"] = v.at;
    return j;
}

json toJson(const SourceRef& v) {
    json j = json::object();
    j["source"] = v.source;
    j["name"] = v.name;
    j["confidence"] = q6(v.confidence);
    j["count"] = v.count;
    j["firstAt"] = v.firstAt;
    j["lastAt"] = v.lastAt;
    return j;
}

json toJson(const ConfidenceContribution& v) {
    json j = json::object();
    j["source"] = v.source;
    j["value"] = q6(v.value);
    j["weightPpm"] = v.weightPpm;
    j["contribution"] = v.contribution;
    return j;
}

json toJson(const EntityTrace& v) {
    json j = json::object();
    j["at"] = v.at;
    j["field"] = v.field;
    j["from"] = v.from;
    j["to"] = v.to;
    j["action"] = v.action;
    j["operatorId"] = v.operatorId;
    j["reason"] = v.reason;
    return j;
}

json toJson(const EntityLink& v) {
    json j = json::object();
    j["kind"] = v.kind;
    j["state"] = v.state;
    j["toId"] = v.toId;
    j["toNo"] = v.toNo;
    j["outgoing"] = v.outgoing;
    return j;
}

json toJson(const EntityRecord& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["missionId"] = v.missionId;
    j["typeKey"] = v.typeKey;
    j["typeName"] = v.typeName;
    j["lng"] = q6(v.lng);
    j["lat"] = q6(v.lat);
    j["alt"] = q6(v.alt);
    json srcs = json::array();
    for (const auto& s : v.sources) srcs.push_back(toJson(s));
    j["sources"] = srcs;
    j["sourceCount"] = v.sourceCount;
    j["multiSource"] = v.multiSource;
    j["confidence"] = q6(v.confidence);
    j["dynamicState"] = v.dynamicState;
    json fl = json::array();
    for (const auto& f : v.flags) fl.push_back(f);
    j["flags"] = fl;
    j["threatScore"] = v.threatScore;
    j["threatBand"] = v.threatBand;
    j["status"] = v.status;
    j["assessed"] = v.assessed;
    j["priority"] = v.priority;
    j["prioritySet"] = v.prioritySet;
    json rels = json::array();
    for (const auto& r : v.relations) rels.push_back(toJson(r));
    j["relations"] = rels;
    json tr = json::array();
    for (const auto& t : v.trace) tr.push_back(toJson(t));
    j["trace"] = tr;
    j["retired"] = v.retired;
    j["retiredAt"] = v.retiredAt;
    j["retireReason"] = v.retireReason;
    j["createdAt"] = v.createdAt;
    j["updatedAt"] = v.updatedAt;
    return j;
}

json toJson(const MergeCandidate& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["typeKey"] = v.typeKey;
    j["distanceM"] = v.distanceM;
    json mk = json::array();
    for (const auto& k : v.matchedKeys) mk.push_back(k);
    j["matchedKeys"] = mk;
    json uk = json::array();
    for (const auto& k : v.unmatchedKeys) uk.push_back(k);
    j["unmatchedKeys"] = uk;
    j["confidence"] = q6(v.confidence);
    return j;
}

json RegisterResult::toJson() const {
    json d = json::object();
    d["status"] = status;
    d["idempotent"] = idempotent;
    d["merged"] = merged;
    d["created"] = created;
    d["entity"] = entity_ledger::toJson(data);
    json cs = json::array();
    for (const auto& c : candidates) cs.push_back(entity_ledger::toJson(c));
    d["candidates"] = cs;
    json contribs = json::array();
    for (const auto& c : contributions) contribs.push_back(entity_ledger::toJson(c));
    d["contributions"] = contribs;
    json um = json::array();
    for (const auto& u : unmet) um.push_back(entity_ledger::toJson(u));
    d["unmet"] = um;
    d["ts"] = ts;
    return envelope(code, message, d);
}

// ---------------------------------------------------------------- 一致性

json toJson(const VisibleItem& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["typeKey"] = v.typeKey;
    j["typeName"] = v.typeName;
    json fl = json::array();
    for (const auto& f : v.flags) fl.push_back(f);
    j["flags"] = fl;
    j["dynamicState"] = v.dynamicState;
    j["threatBand"] = v.threatBand;
    j["status"] = v.status;
    j["threatScore"] = v.threatScore;
    j["confidence"] = q6(v.confidence);
    j["lng"] = q6(v.lng);
    j["lat"] = q6(v.lat);
    return j;
}

json toJson(const ExcludedItem& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["reason"] = v.reason;
    return j;
}

json VisibleSetResult::toJson() const {
    json d = json::object();
    d["missionId"] = missionId;
    d["viewKey"] = viewKey;
    d["viewName"] = viewName;
    d["phaseKey"] = phaseKey;
    d["scenarioKey"] = scenarioKey;
    json its = json::array();
    for (const auto& i : items) its.push_back(entity_ledger::toJson(i));
    d["items"] = its;
    d["total"] = total;
    d["excluded"] = excluded;
    json ex = json::array();
    for (const auto& e : excludedItems) ex.push_back(entity_ledger::toJson(e));
    d["excludedItems"] = ex;
    d["basis"] = basis;
    d["ts"] = ts;
    return envelope(code, message, d);
}

json toJson(const DiffItem& v) {
    // 键序：no, field, views[] 为已冻结的事件负载（protocol.md §4.4），其余为只增字段
    json j = json::object();
    j["no"] = v.no;
    j["field"] = v.field;
    json vs = json::array();
    for (const auto& s : v.views) vs.push_back(s);
    j["views"] = vs;
    j["kind"] = v.kind;
    j["id"] = v.id;
    j["expected"] = v.expected;
    j["actual"] = v.actual;
    j["phaseKey"] = v.phaseKey;
    j["reason"] = v.reason;
    return j;
}

json toJson(const PhaseDelta& v) {
    json j = json::object();
    j["phaseKey"] = v.phaseKey;
    j["count"] = v.count;
    json add = json::array();
    for (int n : v.addedNos) add.push_back(n);
    j["addedNos"] = add;
    json rem = json::array();
    for (int n : v.removedNos) rem.push_back(n);
    j["removedNos"] = rem;
    j["basis"] = v.basis;
    return j;
}

json toJson(const ReclassifyRecord& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["fromType"] = v.fromType;
    j["toType"] = v.toType;
    j["at"] = v.at;
    j["operatorId"] = v.operatorId;
    j["reason"] = v.reason;
    return j;
}

json ConsistencyReport::toJson() const {
    json d = json::object();
    d["missionId"] = missionId;
    d["consistent"] = consistent;
    d["checkedViews"] = checkedViews;
    d["checkedItems"] = checkedItems;
    json diffs = json::array();
    for (const auto& x : this->diffs) diffs.push_back(entity_ledger::toJson(x));
    d["diffs"] = diffs;
    json deltas = json::array();
    for (const auto& x : phaseDeltas) deltas.push_back(entity_ledger::toJson(x));
    d["phaseDeltas"] = deltas;
    json recl = json::array();
    for (const auto& x : reclassifications) recl.push_back(entity_ledger::toJson(x));
    d["reclassifications"] = recl;
    d["phaseKey"] = phaseKey;
    json ev = json::array();
    for (const auto& x : expectedVisible) ev.push_back(entity_ledger::toJson(x));
    d["expectedVisible"] = ev;
    d["ts"] = ts;
    return envelope(code, message, d);
}

// ---------------------------------------------------------------- 评级

json toJson(const FactorScore& v) {
    json j = json::object();
    j["key"] = v.key;
    j["name"] = v.name;
    j["source"] = v.source;
    j["weightPpm"] = v.weightPpm;
    j["normPpm"] = v.normPpm;
    j["contribution"] = v.contribution;
    j["missing"] = v.missing;
    j["missingPolicy"] = v.missingPolicy;
    j["rawNumber"] = q6(v.rawNumber);
    j["rawText"] = v.rawText;
    return j;
}

json ThreatAssessment::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["no"] = no;
    d["missionId"] = missionId;
    d["score"] = score;
    d["band"] = band;
    d["status"] = status;
    d["totalWeightPpm"] = totalWeightPpm;
    d["rejected"] = rejected;
    d["rejectReason"] = rejectReason;
    json fs = json::array();
    for (const auto& f : factors) fs.push_back(entity_ledger::toJson(f));
    d["factors"] = fs;
    json sk = json::array();
    for (const auto& s : skippedFactors) sk.push_back(s);
    d["skippedFactors"] = sk;
    d["ts"] = ts;
    return d;
}

json toJson(const WindowSegment& v) {
    json j = json::object();
    j["fromMs"] = v.fromMs;
    j["toMs"] = v.toMs;
    j["durationMs"] = v.durationMs;
    j["basis"] = v.basis;
    j["predicted"] = v.predicted;
    j["lng"] = q6(v.lng);
    j["lat"] = q6(v.lat);
    j["speedMps"] = q6(v.speedMps);
    j["headingDeg"] = q6(v.headingDeg);
    return j;
}

json StrikeWindow::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["no"] = no;
    d["missionId"] = missionId;
    d["found"] = found;
    d["fromMs"] = fromMs;
    d["toMs"] = toMs;
    d["durationMs"] = durationMs;
    d["leadMs"] = leadMs;
    d["basis"] = basis;
    d["horizonMs"] = horizonMs;
    d["stepMs"] = stepMs;
    d["trackPoints"] = trackPoints;
    d["extrapolated"] = extrapolated;
    json segs = json::array();
    for (const auto& s : segments) segs.push_back(entity_ledger::toJson(s));
    d["segments"] = segs;
    d["ts"] = ts;
    return d;
}

json StrikeWindowResult::toJson() const { return envelope(code, message, data.toJson()); }

// ---------------------------------------------------------------- 排序与序列

json toJson(const RankedEntity& v) {
    json j = json::object();
    j["rank"] = v.rank;
    j["id"] = v.id;
    j["no"] = v.no;
    j["typeKey"] = v.typeKey;
    j["threatScore"] = v.threatScore;
    j["threatBand"] = v.threatBand;
    j["priority"] = v.priority;
    j["prioritySet"] = v.prioritySet;
    j["confidence"] = q6(v.confidence);
    j["sourceCount"] = v.sourceCount;
    j["sequenceIndex"] = v.sequenceIndex;
    json sk = json::array();
    for (const auto& s : v.sortKeys) sk.push_back(s);
    j["sortKeys"] = sk;
    return j;
}

json toJson(const SequenceEntry& v) {
    json j = json::object();
    j["entityId"] = v.entityId;
    j["no"] = v.no;
    j["position"] = v.position;
    j["addedAt"] = v.addedAt;
    j["actor"] = v.actor;
    j["reason"] = v.reason;
    return j;
}

json toJson(const SequenceAuditEntry& v) {
    json j = json::object();
    j["at"] = v.at;
    j["actor"] = v.actor;
    j["action"] = v.action;
    j["entityId"] = v.entityId;
    j["no"] = v.no;
    j["position"] = v.position;
    j["reason"] = v.reason;
    return j;
}

json SequenceResult::toJson() const {
    json d = json::object();
    d["status"] = status;
    d["idempotent"] = idempotent;
    d["missionId"] = missionId;
    d["entityId"] = entityId;
    json seq = json::array();
    for (const auto& s : sequence) seq.push_back(entity_ledger::toJson(s));
    d["sequence"] = seq;
    json um = json::array();
    for (const auto& u : unmet) um.push_back(entity_ledger::toJson(u));
    d["unmet"] = um;
    d["ts"] = ts;
    return envelope(code, message, d);
}

// ---------------------------------------------------------------- 轨迹

json toJson(const TrackPoint& v) {
    json j = json::object();
    j["ts"] = v.ts;
    j["lng"] = q6(v.lng);
    j["lat"] = q6(v.lat);
    j["alt"] = q6(v.alt);
    j["predicted"] = v.predicted;
    if (v.hasSpeed) j["speedMps"] = q6(v.speedMps);
    if (v.hasHeading) j["headingDeg"] = q6(v.headingDeg);
    if (!v.basis.empty()) j["basis"] = v.basis;
    return j;
}

json toJson(const TrackStats& v) {
    json j = json::object();
    j["points"] = v.points;
    j["oldestTs"] = v.oldestTs;
    j["newestTs"] = v.newestTs;
    j["droppedByRetention"] = v.droppedByRetention;
    j["droppedByCap"] = v.droppedByCap;
    j["replacedSamples"] = v.replacedSamples;
    return j;
}

json TrackAppendResult::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["appended"] = appended;
    d["replaced"] = replaced;
    d["ordered"] = ordered;
    d["total"] = total;
    d["ts"] = ts;
    return envelope(code, message, d);
}

json TrackQueryResult::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["no"] = no;
    d["fromMs"] = fromMs;
    d["toMs"] = toMs;
    json pts = json::array();
    for (const auto& p : points) pts.push_back(entity_ledger::toJson(p));
    d["points"] = pts;
    d["totalInRange"] = totalInRange;
    d["returned"] = returned;
    d["truncated"] = truncated;
    d["nextCursor"] = nextCursor;
    d["decimated"] = decimated;
    d["decimatedFrom"] = decimatedFrom;
    d["everyNth"] = everyNth;
    d["minIntervalMs"] = minIntervalMs;
    d["hasPredicted"] = hasPredicted;
    d["stats"] = entity_ledger::toJson(stats);
    return envelope(code, message, d);
}

json toJson(const ReplaySample& v) {
    // map-2d `ReplaySample`：t / lng / lat / heading? / speed? / props?（无 predicted 槽位）
    json j = json::object();
    j["t"] = v.t;
    j["lng"] = q6(v.lng);
    j["lat"] = q6(v.lat);
    if (v.hasHeading) j["heading"] = q6(v.heading);
    if (v.hasSpeed) j["speed"] = q6(v.speed);
    json props = json::object();
    props["predicted"] = v.predicted;
    props["interpolated"] = v.interpolated;
    j["props"] = props;
    return j;
}

json toJson(const ReplayTrack& v) {
    json j = json::object();
    j["id"] = v.id;
    if (!v.label.empty()) j["label"] = v.label;
    if (!v.kind.empty()) j["kind"] = v.kind;
    if (!v.color.empty()) j["color"] = v.color;
    json ss = json::array();
    for (const auto& s : v.samples) ss.push_back(toJson(s));
    j["samples"] = ss;
    return j;
}

json toJson(const ReplayData& v) {
    json j = json::object();
    if (!v.id.empty()) j["id"] = v.id;
    json ts = json::array();
    for (const auto& t : v.tracks) ts.push_back(toJson(t));
    j["tracks"] = ts;
    return j;
}

json TrackTimeline::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["no"] = no;
    d["missionId"] = missionId;
    d["fromMs"] = fromMs;
    d["toMs"] = toMs;
    d["durationMs"] = durationMs;
    d["stepMs"] = stepMs;
    json pts = json::array();
    for (const auto& p : points) pts.push_back(entity_ledger::toJson(p));
    d["points"] = pts;
    d["decimated"] = decimated;
    d["decimatedFrom"] = decimatedFrom;
    d["truncated"] = truncated;
    d["hasPredicted"] = hasPredicted;
    d["replay"] = entity_ledger::toJson(replay);
    return d;
}

json TrackTimelineResult::toJson() const { return envelope(code, message, data.toJson()); }

json RetentionResult::toJson() const {
    json d = json::object();
    d["entities"] = entities;
    d["removedByAge"] = removedByAge;
    d["removedByCap"] = removedByCap;
    d["remaining"] = remaining;
    d["ts"] = ts;
    return envelope(code, message, d);
}

// ---------------------------------------------------------------- 动作

json toJson(const ActionDef& v) {
    json j = json::object();
    j["key"] = v.key;
    j["name"] = v.name;
    json rq = json::array();
    for (const auto& r : v.requires) rq.push_back(r);
    j["requires"] = rq;
    json sf = json::array();
    for (const auto& r : v.setsFlags) sf.push_back(r);
    j["setsFlags"] = sf;
    json cf = json::array();
    for (const auto& r : v.clearsFlags) cf.push_back(r);
    j["clearsFlags"] = cf;
    j["setsDynamicState"] = v.setsDynamicState;
    j["reversible"] = v.reversible;
    j["exclusive"] = v.exclusive;
    j["once"] = v.once;
    j["undoWithinMs"] = v.undoWithinMs;
    j["setsPriority"] = v.setsPriority;
    j["priorityValue"] = v.priorityValue;
    j["addsToSequence"] = v.addsToSequence;
    return j;
}

json toJson(const UnmetItem& v) {
    json j = json::object();
    j["gate"] = v.gate;
    j["reason"] = v.reason;
    if (!v.detail.empty()) j["detail"] = v.detail;
    return j;
}

json toJson(const StateChange& v) {
    json j = json::object();
    j["field"] = v.field;
    j["from"] = v.from;
    j["to"] = v.to;
    return j;
}

json ActionResult::toJson() const {
    json d = json::object();
    d["status"] = status;
    d["idempotent"] = idempotent;
    d["conflict"] = conflict;
    d["entityId"] = entityId;
    d["no"] = no;
    d["missionId"] = missionId;
    d["actionKey"] = actionKey;
    json ch = json::array();
    for (const auto& c : changes) ch.push_back(entity_ledger::toJson(c));
    d["changes"] = ch;
    json um = json::array();
    for (const auto& u : unmet) um.push_back(entity_ledger::toJson(u));
    d["unmet"] = um;
    json sg = json::array();
    for (const auto& g : skippedGates) sg.push_back(g);
    d["skippedGates"] = sg;
    if (state.has_value()) d["state"] = entity_ledger::toJson(*state);
    d["undoDeadline"] = undoDeadline;
    d["ts"] = ts;
    return envelope(code, message, d);
}

json toJson(const ActionLogEntry& v) {
    json j = json::object();
    j["at"] = v.at;
    j["missionId"] = v.missionId;
    j["entityId"] = v.entityId;
    j["no"] = v.no;
    j["actionKey"] = v.actionKey;
    j["actor"] = v.actor;
    j["status"] = v.status;
    j["reversible"] = v.reversible;
    json ch = json::array();
    for (const auto& c : v.changes) ch.push_back(toJson(c));
    j["changes"] = ch;
    j["reason"] = v.reason;
    j["undoneAt"] = v.undoneAt;
    j["undoneBy"] = v.undoneBy;
    return j;
}

// ---------------------------------------------------------------- 情报关联

json toJson(const RelationDef& v) {
    json j = json::object();
    j["key"] = v.key;
    j["name"] = v.name;
    j["cyclic"] = v.cyclic;
    return j;
}

json toJson(const RelationEdge& v) {
    json j = json::object();
    j["missionId"] = v.missionId;
    j["kind"] = v.kind;
    j["state"] = v.state;
    j["fromId"] = v.fromId;
    j["fromNo"] = v.fromNo;
    j["toId"] = v.toId;
    j["toNo"] = v.toNo;
    j["at"] = v.at;
    j["operatorId"] = v.operatorId;
    return j;
}

json toJson(const CyclePath& v) {
    json j = json::object();
    j["missionId"] = v.missionId;
    json ids = json::array();
    for (const auto& s : v.ids) ids.push_back(s);
    j["ids"] = ids;
    json nos = json::array();
    for (int n : v.nos) nos.push_back(n);
    j["nos"] = nos;
    json ks = json::array();
    for (const auto& s : v.kinds) ks.push_back(s);
    j["kinds"] = ks;
    return j;
}

json RelationResult::toJson() const {
    json d = json::object();
    d["status"] = status;
    d["idempotent"] = idempotent;
    d["edge"] = entity_ledger::toJson(edge);
    json cy = json::array();
    for (const auto& s : cycle) cy.push_back(s);
    d["cycle"] = cy;
    json um = json::array();
    for (const auto& u : unmet) um.push_back(entity_ledger::toJson(u));
    d["unmet"] = um;
    d["ts"] = ts;
    return envelope(code, message, d);
}

json toJson(const ChainNode& v) {
    json j = json::object();
    j["id"] = v.id;
    j["no"] = v.no;
    j["typeKey"] = v.typeKey;
    j["depth"] = v.depth;
    j["viaKind"] = v.viaKind;
    j["viaState"] = v.viaState;
    return j;
}

json ChainResult::toJson() const {
    json d = json::object();
    d["entityId"] = entityId;
    d["no"] = no;
    json up = json::array();
    for (const auto& n : upstream) up.push_back(entity_ledger::toJson(n));
    d["upstream"] = up;
    json dn = json::array();
    for (const auto& n : downstream) dn.push_back(entity_ledger::toJson(n));
    d["downstream"] = dn;
    d["relatedCount"] = relatedCount;
    d["depthLimit"] = depthLimit;
    d["truncated"] = truncated;
    d["cycleDetected"] = cycleDetected;
    json cy = json::array();
    for (const auto& c : cycles) cy.push_back(entity_ledger::toJson(c));
    d["cycles"] = cy;
    return envelope(code, message, d);
}

json toJson(const RelationStatItem& v) {
    json j = json::object();
    j["key"] = v.key;
    j["count"] = v.count;
    return j;
}

json RelationStats::toJson() const {
    json d = json::object();
    d["missionId"] = missionId;
    d["edges"] = edges;
    d["entitiesWithRelations"] = entitiesWithRelations;
    d["isolatedEntities"] = isolatedEntities;
    json bk = json::array();
    for (const auto& x : byKind) bk.push_back(entity_ledger::toJson(x));
    d["byKind"] = bk;
    json bs = json::array();
    for (const auto& x : byState) bs.push_back(entity_ledger::toJson(x));
    d["byState"] = bs;
    return d;
}

json toJson(const FlagDef& v) {
    json j = json::object();
    j["key"] = v.key;
    j["name"] = v.name;
    j["unique"] = v.unique;
    json ex = json::array();
    for (const auto& x : v.exclusive) ex.push_back(x);
    j["exclusive"] = ex;
    return j;
}

// ---------------------------------------------------------------- 自述与观测

json toJson(const Capabilities& v) {
    json j = json::object();
    j["policiesLoaded"] = v.policiesLoaded;
    j["schemaVersion"] = v.schemaVersion;
    j["policiesMajor"] = v.policiesMajor;
    j["definitionVersion"] = v.definitionVersion;
    j["persistent"] = v.persistent;
    j["storeList"] = v.storeList;
    j["clockInjected"] = v.clockInjected;
    j["sinkInjected"] = v.sinkInjected;
    j["logInjected"] = v.logInjected;
    j["registeredActionGates"] = v.registeredActionGates;
    j["missions"] = v.missions;
    j["entities"] = v.entities;
    return j;
}

json toJson(const Metrics& v) {
    json j = json::object();
    j["registrations"] = v.registrations;
    j["merges"] = v.merges;
    j["updates"] = v.updates;
    j["splits"] = v.splits;
    j["duplicatesFlagged"] = v.duplicatesFlagged;
    j["reclassifications"] = v.reclassifications;
    j["assessments"] = v.assessments;
    j["windowsComputed"] = v.windowsComputed;
    j["actions"] = v.actions;
    j["actionRejected"] = v.actionRejected;
    j["actionIdempotent"] = v.actionIdempotent;
    j["actionConflicts"] = v.actionConflicts;
    j["trackAppends"] = v.trackAppends;
    j["trackTruncated"] = v.trackTruncated;
    j["trackDecimated"] = v.trackDecimated;
    j["predictions"] = v.predictions;
    j["retentionDropped"] = v.retentionDropped;
    j["relationsAdded"] = v.relationsAdded;
    j["relationsRejected"] = v.relationsRejected;
    j["cycleRejected"] = v.cycleRejected;
    j["consistencyChecks"] = v.consistencyChecks;
    j["consistencyDiffs"] = v.consistencyDiffs;
    j["gateErrors"] = v.gateErrors;
    j["sinkErrors"] = v.sinkErrors;
    j["storeErrors"] = v.storeErrors;
    j["unknownFields"] = v.unknownFields;
    return j;
}

// ---------------------------------------------------------------- 事件负载

json EntityChangeEvent::toJson() const {
    json j = json::object();
    j["entityId"] = entityId;
    j["no"] = no;
    j["missionId"] = missionId;
    j["change"] = change;
    if (!detail.empty()) j["detail"] = detail;
    j["ts"] = ts;
    return j;
}

json TargetStateEvent::toJson() const {
    // 既有冻结负载（protocol.md §4.2）：字段逐字保留；ts 为允许新增的可选字段
    json j = json::object();
    j["targetId"] = targetId;
    j["targetNo"] = targetNo;
    j["threat"] = threat;
    j["confidence"] = q6(confidence);
    j["dynamicState"] = dynamicState;
    j["lng"] = q6(lng);
    j["lat"] = q6(lat);
    j["status"] = status;
    j["ts"] = ts;
    return j;
}

json ConsistencyEvent::toJson() const {
    json j = json::object();
    j["missionId"] = missionId;
    json diffs = json::array();
    for (const auto& x : this->diffs) diffs.push_back(entity_ledger::toJson(x));
    j["diffs"] = diffs;
    j["consistent"] = consistent;
    j["checkedViews"] = checkedViews;
    if (!phaseKey.empty()) j["phaseKey"] = phaseKey;
    j["ts"] = ts;
    return j;
}

}  // namespace entity_ledger
