// entity-ledger · src/util.cc —— 机制辅助（几何、旗标编码、id 生成、台账快照）
//
// 这里只有**机制**：不含任何业务取值（类型名、动作名、阈值、文案）。
#include "internal.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace entity_ledger {
namespace detail {

namespace {
constexpr double kPi = 3.14159265358979323846;
constexpr double kDegToRad = kPi / 180.0;
constexpr double kRadToDeg = 180.0 / kPi;
}  // namespace

double haversineM(double lng1, double lat1, double lng2, double lat2, double radiusM) {
    const double p1 = lat1 * kDegToRad;
    const double p2 = lat2 * kDegToRad;
    const double dp = (lat2 - lat1) * kDegToRad;
    const double dl = (lng2 - lng1) * kDegToRad;
    const double a = std::sin(dp / 2.0) * std::sin(dp / 2.0) +
                     std::cos(p1) * std::cos(p2) * std::sin(dl / 2.0) * std::sin(dl / 2.0);
    const double clamped = a < 0.0 ? 0.0 : (a > 1.0 ? 1.0 : a);
    return 2.0 * radiusM * std::asin(std::sqrt(clamped));
}

double bearingDeg(double lng1, double lat1, double lng2, double lat2) {
    const double p1 = lat1 * kDegToRad;
    const double p2 = lat2 * kDegToRad;
    const double dl = (lng2 - lng1) * kDegToRad;
    const double y = std::sin(dl) * std::cos(p2);
    const double x = std::cos(p1) * std::sin(p2) - std::sin(p1) * std::cos(p2) * std::cos(dl);
    double deg = std::atan2(y, x) * kRadToDeg;
    while (deg < 0.0) deg += 360.0;
    while (deg >= 360.0) deg -= 360.0;
    return deg;
}

void advance(double lng, double lat, double headingDeg, double distanceM, double radiusM,
             double& outLng, double& outLat) {
    const double h = headingDeg * kDegToRad;
    const double north = distanceM * std::cos(h);
    const double east = distanceM * std::sin(h);
    outLat = lat + (north / radiusM) * kRadToDeg;
    const double cosLat = std::cos(lat * kDegToRad);
    const double denom = std::fabs(cosLat) < 1e-12 ? 1e-12 : cosLat;
    outLng = lng + (east / (radiusM * denom)) * kRadToDeg;
}

bool exposedAt(int64_t t, int64_t nowMs, const StrikePattern& p) {
    if (p.cycleMs <= 0) return false;
    int64_t phase = ((t - nowMs) - p.offsetMs) % p.cycleMs;
    if (phase < 0) phase += p.cycleMs;
    return phase < p.exposedMs;
}

std::string joinFlags(const std::vector<std::string>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += v[i];
    }
    return out;
}

std::vector<std::string> splitFlags(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string digest8(const std::string& s) { return fnv1a64Hex(s).substr(0, 8); }

std::string makeEntityId(const std::string& missionId, std::uint64_t serial) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%06llu", static_cast<unsigned long long>(serial));
    return "ent-" + digest8(missionId) + "-" + std::string(buf);
}

std::pair<std::string, std::string> splitGate(const std::string& id) {
    const std::size_t pos = id.find(':');
    if (pos == std::string::npos) return {id, std::string()};
    return {id.substr(0, pos), id.substr(pos + 1)};
}

// ============================================================================
// 台账快照（宿主落库形状；store 收到的就是它）
// ============================================================================

json missionToJson(const MissionState& m) {
    json out = json::object();
    out["missionId"] = m.missionId;
    out["nextNo"] = m.nextNo;
    json used = json::array();
    for (int n : m.usedNos) used.push_back(n);
    out["usedNos"] = used;
    if (m.referenceSet) {
        json r = json::object();
        r["lng"] = m.referenceLng;
        r["lat"] = m.referenceLat;
        out["reference"] = r;
    }
    json ents = json::array();
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        json e = toJson(it->second);
        auto tit = m.tracks.find(id);
        if (tit != m.tracks.end()) {
            json pts = json::array();
            for (const auto& p : tit->second) pts.push_back(toJson(p));
            e["trajectory"] = pts;
        }
        auto sit = m.trackStats.find(id);
        if (sit != m.trackStats.end()) e["trackStats"] = toJson(sit->second);
        auto ait = m.applied.find(id);
        if (ait != m.applied.end()) {
            json keys = json::array();
            for (const auto& k : ait->second) keys.push_back(k);
            e["appliedActions"] = keys;
        }
        auto oit = m.obsKeys.find(id);
        if (oit != m.obsKeys.end()) {
            json keys = json::array();
            for (const auto& k : oit->second) keys.push_back(k);
            e["obsKeys"] = keys;
        }
        ents.push_back(e);
    }
    out["entities"] = ents;
    json rels = json::array();
    for (const auto& r : m.relations) rels.push_back(toJson(r));
    out["relations"] = rels;
    json seq = json::array();
    for (const auto& s : m.sequence) seq.push_back(toJson(s));
    out["sequence"] = seq;
    json audit = json::array();
    for (const auto& s : m.sequenceAudit) audit.push_back(toJson(s));
    out["sequenceAudit"] = audit;
    json logs = json::array();
    for (const auto& l : m.actionLog) logs.push_back(toJson(l));
    out["actionLog"] = logs;
    return out;
}

namespace {

bool readStr(const json& j, const char* key, std::string& out) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return false;
    out = it->get<std::string>();
    return true;
}

double readNum(const json& j, const char* key, double def = 0.0) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return def;
    return it->get<double>();
}

int readInt(const json& j, const char* key, int def = 0) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return def;
    return static_cast<int>(it->get<double>());
}

int64_t readI64(const json& j, const char* key, int64_t def = 0) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return def;
    return static_cast<int64_t>(it->get<double>());
}

bool readBool(const json& j, const char* key, bool def = false) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_boolean()) return def;
    return it->get<bool>();
}

std::vector<std::string> readStrArray(const json& j, const char* key) {
    std::vector<std::string> out;
    auto it = j.find(key);
    if (it == j.end() || !it->is_array()) return out;
    for (const auto& e : *it) {
        if (e.is_string()) out.push_back(e.get<std::string>());
    }
    return out;
}

}  // namespace

bool missionFromJson(const json& j, MissionState& out) {
    if (!j.is_object()) return false;
    MissionState m;
    if (!readStr(j, "missionId", m.missionId)) return false;
    m.nextNo = readInt(j, "nextNo", 0);
    auto uit = j.find("usedNos");
    if (uit != j.end() && uit->is_array()) {
        for (const auto& e : *uit) {
            if (e.is_number()) m.usedNos.insert(static_cast<int>(e.get<double>()));
        }
    }
    auto rit = j.find("reference");
    if (rit != j.end() && rit->is_object()) {
        m.referenceSet = true;
        m.referenceLng = readNum(*rit, "lng");
        m.referenceLat = readNum(*rit, "lat");
    }

    auto eit = j.find("entities");
    if (eit != j.end() && eit->is_array()) {
        for (const auto& e : *eit) {
            if (!e.is_object()) continue;
            EntityRecord rec;
            readStr(e, "id", rec.id);
            if (rec.id.empty()) continue;
            rec.no = readInt(e, "no");
            readStr(e, "missionId", rec.missionId);
            readStr(e, "typeKey", rec.typeKey);
            readStr(e, "typeName", rec.typeName);
            rec.lng = readNum(e, "lng");
            rec.lat = readNum(e, "lat");
            rec.alt = readNum(e, "alt");
            rec.confidence = readNum(e, "confidence");
            rec.sourceCount = readInt(e, "sourceCount");
            rec.multiSource = readBool(e, "multiSource");
            readStr(e, "dynamicState", rec.dynamicState);
            rec.flags = readStrArray(e, "flags");
            auto atr = e.find("attributes");
            if (atr != e.end() && atr->is_object()) rec.attributes = *atr;
            rec.threatScore = readInt(e, "threatScore");
            readStr(e, "threatBand", rec.threatBand);
            readStr(e, "status", rec.status);
            rec.assessed = readBool(e, "assessed");
            rec.priority = readInt(e, "priority");
            rec.prioritySet = readBool(e, "prioritySet");
            rec.retired = readBool(e, "retired");
            rec.retiredAt = readI64(e, "retiredAt");
            readStr(e, "retireReason", rec.retireReason);
            rec.createdAt = readI64(e, "createdAt");
            rec.updatedAt = readI64(e, "updatedAt");

            auto sit = e.find("sources");
            if (sit != e.end() && sit->is_array()) {
                for (const auto& s : *sit) {
                    SourceRef r;
                    readStr(s, "source", r.source);
                    readStr(s, "name", r.name);
                    r.confidence = readNum(s, "confidence");
                    r.count = readInt(s, "count", 1);
                    r.firstAt = readI64(s, "firstAt");
                    r.lastAt = readI64(s, "lastAt");
                    rec.sources.push_back(r);
                }
            }
            auto tit = e.find("trace");
            if (tit != e.end() && tit->is_array()) {
                for (const auto& t : *tit) {
                    EntityTrace tr;
                    tr.at = readI64(t, "at");
                    readStr(t, "field", tr.field);
                    readStr(t, "from", tr.from);
                    readStr(t, "to", tr.to);
                    readStr(t, "action", tr.action);
                    readStr(t, "operatorId", tr.operatorId);
                    readStr(t, "reason", tr.reason);
                    rec.trace.push_back(tr);
                }
            }
            auto pit = e.find("trajectory");
            if (pit != e.end() && pit->is_array()) {
                std::vector<TrackPoint> pts;
                for (const auto& p : *pit) {
                    TrackPoint tp;
                    tp.ts = readI64(p, "ts");
                    tp.lng = readNum(p, "lng");
                    tp.lat = readNum(p, "lat");
                    tp.alt = readNum(p, "alt");
                    pts.push_back(tp);
                }
                m.tracks[rec.id] = pts;
            }
            auto stit = e.find("trackStats");
            if (stit != e.end() && stit->is_object()) {
                TrackStats ts;
                ts.points = readInt(*stit, "points");
                ts.oldestTs = readI64(*stit, "oldestTs");
                ts.newestTs = readI64(*stit, "newestTs");
                ts.droppedByRetention = readI64(*stit, "droppedByRetention");
                ts.droppedByCap = readI64(*stit, "droppedByCap");
                ts.replacedSamples = readI64(*stit, "replacedSamples");
                m.trackStats[rec.id] = ts;
            }
            auto ait = e.find("appliedActions");
            if (ait != e.end() && ait->is_array()) {
                std::set<std::string> keys;
                for (const auto& k : *ait) {
                    if (k.is_string()) keys.insert(k.get<std::string>());
                }
                m.applied[rec.id] = keys;
            }
            auto oit = e.find("obsKeys");
            if (oit != e.end() && oit->is_array()) {
                std::set<std::string> keys;
                for (const auto& k : *oit) {
                    if (k.is_string()) keys.insert(k.get<std::string>());
                }
                m.obsKeys[rec.id] = keys;
            }

            m.order.push_back(rec.id);
            m.byNo[rec.no] = rec.id;
            m.usedNos.insert(rec.no);
            m.entities[rec.id] = rec;
        }
    }

    auto relit = j.find("relations");
    if (relit != j.end() && relit->is_array()) {
        for (const auto& r : *relit) {
            RelationEdge e;
            readStr(r, "missionId", e.missionId);
            readStr(r, "kind", e.kind);
            readStr(r, "state", e.state);
            readStr(r, "fromId", e.fromId);
            readStr(r, "toId", e.toId);
            e.fromNo = readInt(r, "fromNo");
            e.toNo = readInt(r, "toNo");
            e.at = readI64(r, "at");
            readStr(r, "operatorId", e.operatorId);
            m.relations.push_back(e);
        }
    }
    auto seqit = j.find("sequence");
    if (seqit != j.end() && seqit->is_array()) {
        for (const auto& s : *seqit) {
            SequenceEntry e;
            readStr(s, "entityId", e.entityId);
            e.no = readInt(s, "no");
            e.position = readInt(s, "position");
            e.addedAt = readI64(s, "addedAt");
            readStr(s, "actor", e.actor);
            readStr(s, "reason", e.reason);
            m.sequence.push_back(e);
        }
    }
    auto auditit = j.find("sequenceAudit");
    if (auditit != j.end() && auditit->is_array()) {
        for (const auto& s : *auditit) {
            SequenceAuditEntry e;
            e.at = readI64(s, "at");
            readStr(s, "actor", e.actor);
            readStr(s, "action", e.action);
            readStr(s, "entityId", e.entityId);
            e.no = readInt(s, "no");
            e.position = readInt(s, "position");
            readStr(s, "reason", e.reason);
            m.sequenceAudit.push_back(e);
        }
    }
    auto logit = j.find("actionLog");
    if (logit != j.end() && logit->is_array()) {
        for (const auto& l : *logit) {
            ActionLogEntry e;
            e.at = readI64(l, "at");
            readStr(l, "missionId", e.missionId);
            readStr(l, "entityId", e.entityId);
            e.no = readInt(l, "no");
            readStr(l, "actionKey", e.actionKey);
            readStr(l, "actor", e.actor);
            readStr(l, "status", e.status);
            e.reversible = readBool(l, "reversible", true);
            readStr(l, "reason", e.reason);
            e.undoneAt = readI64(l, "undoneAt");
            readStr(l, "undoneBy", e.undoneBy);
            auto cit = l.find("changes");
            if (cit != l.end() && cit->is_array()) {
                for (const auto& cc : *cit) {
                    StateChange sc;
                    readStr(cc, "field", sc.field);
                    readStr(cc, "from", sc.from);
                    readStr(cc, "to", sc.to);
                    e.changes.push_back(sc);
                }
            }
            m.actionLog.push_back(e);
        }
    }

    if (m.nextNo <= 0) {
        int mx = 0;
        for (int n : m.usedNos) mx = std::max(mx, n);
        m.nextNo = mx + 1;
    }
    out = std::move(m);
    return true;
}

}  // namespace detail
}  // namespace entity_ledger
