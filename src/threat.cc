// entity-ledger · src/threat.cc —— 威胁评级与打击窗口（ELG-RATE）
//
// 权威依据：
//   · ELG-RATE-01 评级规则可注入（因子 / 权重 / 分档阈值全部由规则声明；引擎内无字面量判断）
//   · ELG-RATE-02 打分可复算（输出逐因子得分与总分；Σ contribution == score）
//   · ELG-RATE-03 分档由阈值决定（bands 有序查找，不是布尔判断）
//   · ELG-RATE-04 距离因子用真实几何（haversine，半径由规则注入；不做占位）
//   · ELG-RATE-05 评级输入显式（ThreatSnapshot；不读全局状态、不读数据库）
//   · ELG-RATE-06 打击窗口由轨迹与暴露规律**计算**得出，输出结构化时间区间
//     （现状硬编码字符串 MUST 移除；本文件内无任何窗口数值常量）
//
// 复算口径（写进契约文档）：
//   contribution_i = round_half_up(normPpm_i * weightPpm_i * 100 / (totalWeightPpm * 1e6))
//   score          = Σ contribution_i          （**逐项贡献求和**，逐项可手算核对）
//   归一化前，输入先量化为整数（距离取整到米、比例取整到 ppm），因此"手算 == 引擎值"。
#include "internal.h"

#include <algorithm>
#include <cmath>

namespace entity_ledger {

using detail::Definition;
using detail::FactorDef;
using detail::MissionState;
using detail::State;

namespace {

}  // namespace

namespace detail {

ThreatSnapshot snapshotOf(const EntityRecord& rec) {
    ThreatSnapshot s;
    s.entityId = rec.id;
    s.no = rec.no;
    s.missionId = rec.missionId;
    s.typeKey = rec.typeKey;
    s.lng = rec.lng;
    s.lat = rec.lat;
    s.confidence = rec.confidence;
    s.dynamicState = rec.dynamicState;
    s.sourceCount = static_cast<int>(rec.sources.size());
    s.flagKeys = rec.flags;
    s.attributes = rec.attributes;
    s.observedAt = rec.updatedAt;
    return s;
}

ThreatAssessment computeAssessment(const Definition& def, const ThreatSnapshot& snap, bool refSet,
                                   double refLng, double refLat, int64_t ts) {
    ThreatAssessment out;
    out.entityId = snap.entityId;
    out.no = snap.no;
    out.missionId = snap.missionId;
    out.ts = ts;

    // 基准点：快照优先，其次任务基准点
    const bool useRef = snap.referenceSet || refSet;
    const double useLng = snap.referenceSet ? snap.referenceLng : refLng;
    const double useLat = snap.referenceSet ? snap.referenceLat : refLat;

    std::vector<FactorScore> scores;
    int64_t weightSum = 0;

    for (const FactorDef& f : def.factors) {
        FactorScore fs;
        fs.key = f.key;
        fs.name = f.name;
        fs.source = f.source;
        fs.weightPpm = static_cast<int>(f.weightPpm);
        fs.missingPolicy = f.missing;

        bool have = false;
        double raw = 0.0;
        std::string rawText;
        int64_t rawInt = 0;  // 归一化的整数输入

        if (f.source == "typeBase") {
            const EntityType* t = def.findType(snap.typeKey);
            if (t) {
                raw = t->baseThreat;
                rawInt = static_cast<int64_t>(std::llround(clamp01(raw) * 1000000.0));
                have = true;
            }
        } else if (f.source == "distance") {
            if (useRef) {
                const double d = detail::haversineM(useLng, useLat, snap.lng, snap.lat, def.earthRadiusM);
                raw = static_cast<double>(std::llround(d));  // 量化到米（可手算）
                rawInt = static_cast<int64_t>(std::llround(raw));
                have = true;
            }
        } else if (f.source == "state") {
            if (!snap.dynamicState.empty()) {
                rawText = snap.dynamicState;
                have = true;
            }
        } else if (f.source == "confidence") {
            raw = clamp01(snap.confidence);
            rawInt = static_cast<int64_t>(std::llround(raw * 1000000.0));
            have = true;
        } else if (f.source == "sourceCount") {
            raw = static_cast<double>(snap.sourceCount);
            rawInt = snap.sourceCount;
            have = true;
        } else if (f.source == "attribute") {
            auto it = snap.attributes.find(f.attributeKey);
            if (it != snap.attributes.end()) {
                if (it->is_number()) {
                    raw = it->get<double>();
                    rawInt = static_cast<int64_t>(std::llround(raw));
                    have = true;
                } else if (it->is_string()) {
                    rawText = it->get<std::string>();
                    have = true;
                }
            }
        }

        if (!have) {
            fs.missing = true;
            if (f.missing == "reject") {
                out.rejected = true;
                if (out.rejectReason.empty()) out.rejectReason = f.key;
            } else if (f.missing == "skip") {
                out.skippedFactors.push_back(f.key);
                scores.push_back(fs);
                continue;  // 不进入分母（权重重新归一）
            }
            // 缺省 zero：normPpm = 0
            scores.push_back(fs);
            weightSum += f.weightPpm;
            continue;
        }

        fs.rawNumber = raw;
        fs.rawText = rawText;
        int normPpm = 0;
        if (f.normalizeType == "percent" || f.normalizeType == "identity") {
            normPpm = static_cast<int>(detail::roundHalfUp(rawInt, 1));
        } else if (f.normalizeType == "range") {
            const double span = f.normMax - f.normMin;
            double t = span == 0.0 ? 0.0 : (raw - f.normMin) / span;
            t = clamp01(t);
            if (f.direction == "lower") t = 1.0 - t;
            normPpm = static_cast<int>(detail::roundHalfUp(
                static_cast<int64_t>(std::llround(t * 1000000.0)), 1));
        } else if (f.normalizeType == "table") {
            auto it = f.table.find(rawText);
            if (it == f.table.end()) {
                fs.missing = true;
                if (f.missing == "reject") {
                    out.rejected = true;
                    if (out.rejectReason.empty()) out.rejectReason = f.key;
                } else if (f.missing == "skip") {
                    out.skippedFactors.push_back(f.key);
                    scores.push_back(fs);
                    continue;
                }
                normPpm = 0;
            } else {
                normPpm = static_cast<int>(detail::roundHalfUp(
                    static_cast<int64_t>(std::llround(clamp01(it->second) * 1000000.0)), 1));
            }
        }
        fs.normPpm = normPpm;
        weightSum += f.weightPpm;
        scores.push_back(fs);
    }

    out.totalWeightPpm = static_cast<int>(weightSum);
    int score = 0;
    if (weightSum > 0) {
        for (auto& fs : scores) {
            if (fs.missing && fs.missingPolicy == "skip") continue;
            const int64_t num = static_cast<int64_t>(fs.normPpm) * fs.weightPpm * 100;
            const int64_t den = weightSum * 1000000;
            fs.contribution = static_cast<int>(detail::roundHalfUp(num, den));
            score += fs.contribution;
        }
    }
    out.score = static_cast<int>(clampI64(score, 0, 100));
    const detail::BandDef* band = def.bandFor(out.score);
    if (band) {
        out.band = band->key;
        out.status = band->state;
    }
    out.factors = std::move(scores);
    return out;
}

}  // namespace detail

// ============================================================================
// 公开入口：评级
// ============================================================================

ThreatAssessment EntityLedger::assessThreat(const ThreatSnapshot& snapshot) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    const int64_t now = st.nowLocked();
    bool refSet = false;
    double refLng = 0.0, refLat = 0.0;
    auto mit = st.missions.find(snapshot.missionId);
    if (mit != st.missions.end() && mit->second.referenceSet) {
        refSet = true;
        refLng = mit->second.referenceLng;
        refLat = mit->second.referenceLat;
    } else if (st.def.referenceSet) {
        refSet = true;
        refLng = st.def.referenceLng;
        refLat = st.def.referenceLat;
    }
    return detail::computeAssessment(st.def, snapshot, refSet, refLng, refLat, now);
}

ThreatAssessment EntityLedger::assessEntity(const std::string& entityId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    const int64_t now = st.nowLocked();
    for (auto& kv : st.missions) {
        auto it = kv.second.entities.find(entityId);
        if (it == kv.second.entities.end()) continue;
        bool refSet = false;
        double refLng = 0.0, refLat = 0.0;
        if (kv.second.referenceSet) {
            refSet = true;
            refLng = kv.second.referenceLng;
            refLat = kv.second.referenceLat;
        } else if (st.def.referenceSet) {
            refSet = true;
            refLng = st.def.referenceLng;
            refLat = st.def.referenceLat;
        }
        return detail::computeAssessment(st.def, detail::snapshotOf(it->second), refSet, refLng,
                                        refLat, now);
    }
    ThreatAssessment empty;
    empty.entityId = entityId;
    empty.rejected = true;
    empty.rejectReason = "entity-not-found";
    return empty;
}

int EntityLedger::refreshThreats(const std::string& missionId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    const int64_t now = st.nowLocked();
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return 0;
    MissionState& m = mit->second;
    MissionState backup = m;
    bool refSet = false;
    double refLng = 0.0, refLat = 0.0;
    if (m.referenceSet) {
        refSet = true;
        refLng = m.referenceLng;
        refLat = m.referenceLat;
    } else if (st.def.referenceSet) {
        refSet = true;
        refLng = st.def.referenceLng;
        refLat = st.def.referenceLat;
    }
    int n = 0;
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        const ThreatAssessment a =
            detail::computeAssessment(st.def, detail::snapshotOf(it->second), refSet, refLng,
                                      refLat, now);
        it->second.threatScore = a.score;
        it->second.threatBand = a.band;
        it->second.status = a.status;
        it->second.assessed = true;
        ++n;
        ++st.metrics.assessments;
    }
    if (!st.persistLocked(m)) {
        m = std::move(backup);
        return 0;
    }
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        st.emitTargetState(it->second, now);
    }
    return n;
}

// ============================================================================
// 打击窗口（ELG-RATE-06：结构化时间区间，由轨迹外推 + 规则暴露规律推算）
// ============================================================================

StrikeWindowResult EntityLedger::strikeWindow(const std::string& entityId,
                                              const StrikeWindowQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    StrikeWindowResult res;
    const int64_t now = q.nowMs > 0 ? q.nowMs : st.nowLocked();
    res.data.ts = now;

    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(entityId);
        if (eit == kv.second.entities.end()) continue;
        const EntityRecord& rec = eit->second;
        res.data.entityId = rec.id;
        res.data.no = rec.no;
        res.data.missionId = kv.first;

        const detail::StrikeWindowRule& w = st.def.window;
        const int64_t horizon = q.horizonOverrideMs > 0 ? q.horizonOverrideMs : w.horizonMs;
        res.data.horizonMs = static_cast<int>(horizon);
        res.data.stepMs = static_cast<int>(w.stepMs);

        auto tit = kv.second.tracks.find(entityId);
        const std::vector<TrackPoint>* pts =
            tit == kv.second.tracks.end() ? nullptr : &tit->second;
        const int pointCount = pts ? static_cast<int>(pts->size()) : 0;
        res.data.trackPoints = pointCount;

        if (pointCount < w.minPoints) {
            res.code = 0;
            res.message = "insufficient-track";
            return res;
        }
        if (w.patterns.empty()) {
            res.code = 0;
            res.message = "no-exposure-rule";
            return res;
        }
        const detail::StrikePattern* pattern = nullptr;
        for (const auto& p : w.patterns) {
            for (const auto& t : p.appliesToTypes) {
                if (t == "*" || t == rec.typeKey) {
                    pattern = &p;
                    break;
                }
            }
            if (pattern) break;
        }
        if (!pattern) {
            res.code = 0;
            res.message = "no-exposure-rule";
            return res;
        }

        // 轨迹外推：末两点定速度与航向（确定性；不足两点时上面的 minPoints 已拦下）
        const TrackPoint& last = pts->back();
        const TrackPoint& prev = pts->at(pts->size() - 2);
        const int64_t dt = last.ts - prev.ts;
        if (dt <= 0) {
            res.code = 0;
            res.message = "invalid-track-interval";
            return res;
        }
        const double dist = detail::haversineM(prev.lng, prev.lat, last.lng, last.lat, st.def.earthRadiusM);
        const double speed = dist / (static_cast<double>(dt) / 1000.0);
        const double heading = detail::bearingDeg(prev.lng, prev.lat, last.lng, last.lat);
        res.data.extrapolated = true;

        // 扫掠暴露区间（半开区间；边界量化到 stepMs 网格，确定性）
        struct Seg {
            int64_t from;
            int64_t to;
        };
        std::vector<Seg> segs;
        bool open = false;
        int64_t openFrom = 0;
        for (int64_t t = now; t < now + horizon; t += w.stepMs) {
            const bool ex = detail::exposedAt(t, now, *pattern);
            if (ex && !open) {
                open = true;
                openFrom = t;
            } else if (!ex && open) {
                open = false;
                segs.push_back(Seg{openFrom, t});
            }
        }
        if (open) segs.push_back(Seg{openFrom, now + horizon});

        const double radius = st.def.earthRadiusM;
        for (const auto& s : segs) {
            WindowSegment ws;
            ws.fromMs = s.from;
            ws.toMs = s.to;
            ws.durationMs = s.to - s.from;
            ws.basis = pattern->key;
            ws.predicted = true;
            ws.speedMps = speed;
            ws.headingDeg = heading;
            const double advanceM = speed * (static_cast<double>(s.from - last.ts) / 1000.0);
            detail::advance(last.lng, last.lat, heading, advanceM, radius, ws.lng, ws.lat);
            res.data.segments.push_back(ws);
        }
        for (const auto& s : res.data.segments) {
            if (s.durationMs >= w.minDurationMs) {
                res.data.found = true;
                res.data.fromMs = s.fromMs;
                res.data.toMs = s.toMs;
                res.data.durationMs = s.durationMs;
                res.data.leadMs = s.fromMs - now;
                res.data.basis = s.basis;
                break;
            }
        }
        res.code = 0;
        res.message = res.data.found ? "ok" : "no-window-within-horizon";
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

}  // namespace entity_ledger
