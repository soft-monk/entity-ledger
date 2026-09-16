// entity-ledger · src/track.cc —— 轨迹服务（ELG-TRK）
//
// 权威依据：
//   · ELG-TRK-01 轨迹写入按 ts 有序（**乱序写入后查询仍有序**：写入即插入有序位置）
//   · ELG-TRK-02 区间查询 [from, to)：分页/上限截断且**不静默丢**（truncated + nextCursor）
//   · ELG-TRK-03 抽稀（everyNth / 最小时间间隔）且**如实标注**（decimated + decimatedFrom + 生效参数）
//   · ELG-TRK-04 时间轴输出：`replay` 子结构**逐字段对齐 map-2d `ReplayData`**
//               （`{id?, tracks:[{id,label?,kind?,color?,samples:[{t,lng,lat,heading?,speed?,props?}]}]}`，
//               时间戳为 epoch 毫秒；由宿主适配层喂 `mapCommands.loadReplay`）
//   · ELG-TRK-05 预测点显式标记（predicted=true + basis），不与实测混淆
//   · ELG-TRK-06 保留策略可配，清理计数可查
//
// 实测轨迹**只**保存实测点；预测点只出现在预测查询与（可选）时间轴输出中，永不入库。
#include "internal.h"

#include <algorithm>
#include <cmath>

namespace entity_ledger {

namespace {

using detail::MissionState;
using detail::State;
using detail::TrackRule;

std::vector<TrackPoint>::iterator lowerBoundTs(std::vector<TrackPoint>& v, int64_t ts) {
    return std::lower_bound(v.begin(), v.end(), ts,
                            [](const TrackPoint& p, int64_t t) { return p.ts < t; });
}

/// 区间内下标（[from, to)；from<=0 = 无下界，to<=0 = 无上界）
std::vector<std::size_t> rangeIndices(const std::vector<TrackPoint>& v, int64_t from, int64_t to) {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (from > 0 && v[i].ts < from) continue;
        if (to > 0 && v[i].ts >= to) continue;
        out.push_back(i);
    }
    return out;
}

/// 抽稀：先 everyNth（区间内第 1 个起每 N 个留 1），再 minIntervalMs（首个必留）
std::vector<std::size_t> decimate(const std::vector<TrackPoint>& v,
                                  const std::vector<std::size_t>& idx, int everyNth,
                                  int64_t minIntervalMs) {
    std::vector<std::size_t> out;
    int64_t lastKept = 0;
    bool hasLast = false;
    for (std::size_t k = 0; k < idx.size(); ++k) {
        if (everyNth > 1 && (k % static_cast<std::size_t>(everyNth)) != 0) continue;
        const TrackPoint& p = v[idx[k]];
        if (minIntervalMs > 0 && hasLast && (p.ts - lastKept) < minIntervalMs) continue;
        out.push_back(idx[k]);
        lastKept = p.ts;
        hasLast = true;
    }
    return out;
}

/// 空间度量（速度/航向）由相邻实测点推算。**只重算受影响的下标**（O(1)/次写入，
/// 使万点级写入保持线性；ELG-NFR-05 的前提）。
void annotateAt(std::vector<TrackPoint>& pts, std::size_t i, double radiusM) {
    if (i == 0 || i >= pts.size()) return;
    const int64_t dt = pts[i].ts - pts[i - 1].ts;
    if (dt <= 0) return;
    const double d =
        detail::haversineM(pts[i - 1].lng, pts[i - 1].lat, pts[i].lng, pts[i].lat, radiusM);
    pts[i].speedMps = d / (static_cast<double>(dt) / 1000.0);
    pts[i].hasSpeed = true;
    pts[i].headingDeg = detail::bearingDeg(pts[i - 1].lng, pts[i - 1].lat, pts[i].lng, pts[i].lat);
    pts[i].hasHeading = true;
}

void annotate(std::vector<TrackPoint>& pts, double radiusM) {
    for (std::size_t i = 1; i < pts.size(); ++i) annotateAt(pts, i, radiusM);
}

ReplaySample toSample(const TrackPoint& p) {
    ReplaySample s;
    s.t = p.ts;
    s.lng = p.lng;
    s.lat = p.lat;
    if (p.hasHeading) {
        s.hasHeading = true;
        s.heading = p.headingDeg;
    }
    if (p.hasSpeed) {
        s.hasSpeed = true;
        s.speed = p.speedMps;
    }
    s.predicted = p.predicted;
    return s;
}

}  // namespace

// ============================================================================
// 写入（ELG-TRK-01）
// ============================================================================

TrackAppendResult EntityLedger::appendTrack(const TrackInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    TrackAppendResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = in.entityId;
    if (in.entityId.empty()) {
        res.code = 1000;
        res.message = "entityId is required";
        return res;
    }
    if (in.point.ts <= 0) {
        res.code = 1000;
        res.message = "point ts is required (epoch ms)";
        return res;
    }
    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(in.entityId);
        if (eit == kv.second.entities.end()) continue;
        MissionState& m = kv.second;
        std::vector<TrackPoint>& pts = m.tracks[in.entityId];
        TrackStats& stats = m.trackStats[in.entityId];

        // upsert：同 ts 覆盖（确定性；避免回放出现重复时间戳）
        auto it = lowerBoundTs(pts, in.point.ts);
        bool replaced = false;
        std::size_t insertAt = static_cast<std::size_t>(it - pts.begin());
        TrackPoint saved;
        bool hasSaved = false;
        if (it != pts.end() && it->ts == in.point.ts) {
            saved = *it;
            hasSaved = true;
            *it = in.point;
            replaced = true;
        } else {
            pts.insert(it, in.point);  // 乱序写入：插入即有序
        }
        // 只重算受影响的下标（写入保持 O(1) 摊还，万点级可用；ELG-NFR-05）
        const std::size_t touched = static_cast<std::size_t>(it - pts.begin());
        annotateAt(pts, touched, st.def.earthRadiusM);
        annotateAt(pts, touched + 1, st.def.earthRadiusM);

        int dropped = 0;
        if (st.def.track.maxPointsPerEntity > 0 &&
            static_cast<int>(pts.size()) > st.def.track.maxPointsPerEntity) {
            const int excess = static_cast<int>(pts.size()) - st.def.track.maxPointsPerEntity;
            pts.erase(pts.begin(), pts.begin() + excess);
            dropped = excess;
            stats.droppedByCap += excess;
        }
        stats.points = static_cast<int>(pts.size());
        if (!pts.empty()) {
            stats.oldestTs = pts.front().ts;
            stats.newestTs = pts.back().ts;
        }
        if (replaced) stats.replacedSamples += 1;

        if (!st.persistLocked(m)) {
            // 回滚（写前提交失败 → 内存不变）
            if (replaced) {
                if (hasSaved) pts[insertAt] = saved;
            } else if (insertAt < pts.size()) {
                pts.erase(pts.begin() + static_cast<long>(insertAt));
            }
            stats.droppedByCap -= dropped;
            stats.points = static_cast<int>(pts.size());
            if (replaced) stats.replacedSamples -= 1;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.trackAppends;
        res.code = 0;
        res.message = replaced ? "replaced" : "appended";
        res.appended = replaced ? 0 : 1;
        res.replaced = replaced ? 1 : 0;
        res.ordered = true;
        res.total = static_cast<int>(pts.size());
        st.emitEntityChanged(kv.first, eit->second, "trajectory",
                             std::to_string(in.point.ts), now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

TrackAppendResult EntityLedger::appendTrackBatch(const std::string& entityId,
                                                 const std::vector<TrackPoint>& points) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    TrackAppendResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = entityId;
    if (entityId.empty() || points.empty()) {
        res.code = 1000;
        res.message = "entityId and points are required";
        return res;
    }
    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(entityId);
        if (eit == kv.second.entities.end()) continue;
        MissionState& m = kv.second;
        std::vector<TrackPoint>& pts = m.tracks[entityId];
        TrackStats& stats = m.trackStats[entityId];
        const std::vector<TrackPoint> backupPts = pts;
        const TrackStats backupStats = stats;
        for (const auto& p : points) {
            if (p.ts <= 0) continue;
            auto it = lowerBoundTs(pts, p.ts);
            const std::size_t at = static_cast<std::size_t>(it - pts.begin());
            if (it != pts.end() && it->ts == p.ts) {
                *it = p;
                ++res.replaced;
                stats.replacedSamples += 1;
            } else {
                pts.insert(it, p);
                ++res.appended;
            }
            annotateAt(pts, at, st.def.earthRadiusM);
            annotateAt(pts, at + 1, st.def.earthRadiusM);
        }
        if (st.def.track.maxPointsPerEntity > 0 &&
            static_cast<int>(pts.size()) > st.def.track.maxPointsPerEntity) {
            const int excess = static_cast<int>(pts.size()) - st.def.track.maxPointsPerEntity;
            pts.erase(pts.begin(), pts.begin() + excess);
            stats.droppedByCap += excess;
        }
        stats.points = static_cast<int>(pts.size());
        if (!pts.empty()) {
            stats.oldestTs = pts.front().ts;
            stats.newestTs = pts.back().ts;
        }
        if (!st.persistLocked(m)) {  // 批量只落盘一次（ELG-NFR-05 的写入路径）
            pts = backupPts;
            stats = backupStats;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        st.metrics.trackAppends += res.appended;
        res.code = 0;
        res.message = "ok";
        res.ordered = true;
        res.total = static_cast<int>(pts.size());
        st.emitEntityChanged(kv.first, eit->second, "trajectory-batch",
                             std::to_string(res.appended), now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

// ============================================================================
// 区间查询（ELG-TRK-02/03）
// ============================================================================

TrackQueryResult EntityLedger::queryTrack(const TrackQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    TrackQueryResult res;
    res.entityId = q.entityId;
    res.fromMs = q.fromMs;
    res.toMs = q.toMs;
    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(q.entityId);
        if (eit == kv.second.entities.end()) continue;
        res.no = eit->second.no;
        auto tit = kv.second.tracks.find(q.entityId);
        if (tit == kv.second.tracks.end()) {
            res.code = 0;
            res.message = "no track";
            return res;
        }
        const std::vector<TrackPoint>& pts = tit->second;
        const std::vector<std::size_t> idx = rangeIndices(pts, q.fromMs, q.toMs);
        res.totalInRange = static_cast<int>(idx.size());
        res.everyNth = q.everyNth > 0 ? q.everyNth : st.def.track.decimateEveryNth;
        res.minIntervalMs =
            q.minIntervalMs > 0 ? q.minIntervalMs : st.def.track.decimateMinIntervalMs;
        const std::vector<std::size_t> kept =
            decimate(pts, idx, res.everyNth, res.minIntervalMs);
        res.decimatedFrom = static_cast<int>(idx.size());
        res.decimated = kept.size() < idx.size();

        std::vector<std::size_t> ordered = kept;
        if (q.descending) std::reverse(ordered.begin(), ordered.end());

        const int limit = q.limit > 0 ? q.limit : 0;
        std::size_t begin = 0;
        if (q.offset > 0) {
            if (static_cast<std::size_t>(q.offset) >= ordered.size()) {
                res.code = 0;
                res.message = "offset beyond result";
                res.truncated = true;
                res.nextCursor = 0;
                return res;
            }
            begin = static_cast<std::size_t>(q.offset);
        }
        std::size_t end = ordered.size();
        if (limit > 0 && static_cast<std::size_t>(limit) < ordered.size() - begin) {
            end = begin + static_cast<std::size_t>(limit);
            res.truncated = true;  // MUST NOT 静默丢：截断必须被标注
            res.nextCursor = pts[ordered[end]].ts;
        }
        for (std::size_t i = begin; i < end; ++i) {
            TrackPoint p = pts[ordered[i]];
            if (p.predicted) res.hasPredicted = true;
            res.points.push_back(p);
        }
        res.returned = static_cast<int>(res.points.size());
        auto sit = kv.second.trackStats.find(q.entityId);
        if (sit != kv.second.trackStats.end()) {
            res.stats = sit->second;
        } else {
            res.stats.points = static_cast<int>(pts.size());
            if (!pts.empty()) {
                res.stats.oldestTs = pts.front().ts;
                res.stats.newestTs = pts.back().ts;
            }
        }
        if (res.truncated) ++st.metrics.trackTruncated;
        if (res.decimated) ++st.metrics.trackDecimated;
        res.code = 0;
        res.message = "ok";
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

TrackStats EntityLedger::trackStats(const std::string& entityId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    for (auto& kv : st.missions) {
        auto sit = kv.second.trackStats.find(entityId);
        if (sit != kv.second.trackStats.end()) return sit->second;
        auto tit = kv.second.tracks.find(entityId);
        if (tit != kv.second.tracks.end()) {
            TrackStats s;
            s.points = static_cast<int>(tit->second.size());
            if (!tit->second.empty()) {
                s.oldestTs = tit->second.front().ts;
                s.newestTs = tit->second.back().ts;
            }
            return s;
        }
    }
    return TrackStats{};
}

// ============================================================================
// 预测（ELG-TRK-05：显式标记，不与实测混淆）
// ============================================================================

TrackQueryResult EntityLedger::predictTrack(const PredictQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    TrackQueryResult res;
    res.entityId = q.entityId;
    const int64_t now = q.nowMs > 0 ? q.nowMs : st.nowLocked();
    const TrackRule& rule = st.def.track;
    const int64_t horizon = q.horizonMs > 0 ? q.horizonMs : rule.predictHorizonMs;
    const int64_t step = q.stepMs > 0 ? q.stepMs : rule.predictStepMs;
    const int maxPoints = q.maxPoints > 0 ? q.maxPoints : rule.predictMaxPoints;

    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(q.entityId);
        if (eit == kv.second.entities.end()) continue;
        res.no = eit->second.no;
        auto tit = kv.second.tracks.find(q.entityId);
        if (tit == kv.second.tracks.end() ||
            static_cast<int>(tit->second.size()) < rule.predictMinPoints) {
            res.code = 0;
            res.message = "insufficient-track";
            return res;
        }
        const std::vector<TrackPoint>& pts = tit->second;
        const TrackPoint& last = pts.back();
        const TrackPoint& prev = pts[pts.size() - 2];
        const int64_t dt = last.ts - prev.ts;
        if (dt <= 0) {
            res.code = 0;
            res.message = "invalid-track-interval";
            return res;
        }
        const double d = detail::haversineM(prev.lng, prev.lat, last.lng, last.lat, st.def.earthRadiusM);
        const double speed = d / (static_cast<double>(dt) / 1000.0);
        const double heading = detail::bearingDeg(prev.lng, prev.lat, last.lng, last.lat);
        for (int i = 1; i <= maxPoints; ++i) {
            const int64_t ahead = i * step;
            if (ahead > horizon) break;
            TrackPoint p;
            p.ts = last.ts + ahead;
            if (p.ts <= now) continue;  // 只给"未来"的点
            const double advanceM = speed * (static_cast<double>(ahead) / 1000.0);
            detail::advance(last.lng, last.lat, heading, advanceM, st.def.earthRadiusM, p.lng,
                            p.lat);
            p.alt = last.alt;
            p.predicted = true;
            p.basis = "extrapolation";
            p.speedMps = speed;
            p.hasSpeed = true;
            p.headingDeg = heading;
            p.hasHeading = true;
            res.points.push_back(p);
        }
        res.totalInRange = static_cast<int>(res.points.size());
        res.returned = res.totalInRange;
        res.hasPredicted = true;
        res.stats.points = static_cast<int>(pts.size());
        res.stats.oldestTs = pts.front().ts;
        res.stats.newestTs = pts.back().ts;
        res.code = 0;
        res.message = res.points.empty() ? "no-future-points" : "ok";
        ++st.metrics.predictions;
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

// ============================================================================
// 时间轴输出（ELG-TRK-04：形状对齐 map-2d `ReplayData`，由宿主适配）
// ============================================================================

TrackTimelineResult EntityLedger::trackTimeline(const TrackTimelineQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    TrackTimelineResult res;
    res.data.entityId = q.entityId;
    for (auto& kv : st.missions) {
        auto eit = kv.second.entities.find(q.entityId);
        if (eit == kv.second.entities.end()) continue;
        res.data.no = eit->second.no;
        res.data.missionId = kv.first;
        auto tit = kv.second.tracks.find(q.entityId);
        if (tit == kv.second.tracks.end() || tit->second.empty()) {
            res.code = 0;
            res.message = "no track";
            return res;
        }
        const std::vector<TrackPoint>& pts = tit->second;
        const std::vector<std::size_t> idx = rangeIndices(pts, q.fromMs, q.toMs);
        std::vector<TrackPoint> real;
        for (std::size_t i : idx) real.push_back(pts[i]);
        if (real.empty()) {
            res.code = 0;
            res.message = "empty-range";
            return res;
        }
        annotate(real, st.def.earthRadiusM);

        const int64_t step = q.stepMs > 0 ? q.stepMs : st.def.track.timelineStepMs;
        res.data.stepMs = static_cast<int>(step);
        res.data.points = real;
        res.data.decimated = false;
        res.data.decimatedFrom = static_cast<int>(real.size());

        if (step > 1 && real.size() > 1) {
            // 重采样：线性插值（插值点在回放里标注 interpolated=true，不与实测混淆）
            std::vector<TrackPoint> sampled;
            const int64_t t0 = real.front().ts;
            const int64_t t1 = real.back().ts;
            std::size_t j = 0;
            for (int64_t t = t0; t <= t1; t += step) {
                while (j + 1 < real.size() && real[j + 1].ts < t) ++j;
                if (j + 1 < real.size() && real[j].ts <= t && t <= real[j + 1].ts) {
                    TrackPoint p;
                    const int64_t span = real[j + 1].ts - real[j].ts;
                    const double w = span <= 0 ? 0.0
                                               : static_cast<double>(t - real[j].ts) /
                                                     static_cast<double>(span);
                    p.ts = t;
                    p.lng = real[j].lng + (real[j + 1].lng - real[j].lng) * w;
                    p.lat = real[j].lat + (real[j + 1].lat - real[j].lat) * w;
                    p.alt = real[j].alt + (real[j + 1].alt - real[j].alt) * w;
                    const bool exact = (t == real[j].ts || t == real[j + 1].ts);
                    p.predicted = false;
                    p.basis = exact ? "" : "interpolated";
                    sampled.push_back(p);
                }
            }
            if (!sampled.empty()) res.data.points = sampled;
            res.data.decimated = res.data.points.size() < real.size();
        }

        if (q.includePredicted || st.def.track.timelineIncludePredicted) {
            PredictQuery pq;
            pq.entityId = q.entityId;
            pq.horizonMs = st.def.track.predictHorizonMs;
            const TrackQueryResult pr = predictTrack(pq);
            for (const auto& p : pr.points) {
                res.data.points.push_back(p);
                res.data.hasPredicted = true;
            }
        }

        if (!res.data.points.empty()) {
            res.data.fromMs = res.data.points.front().ts;
            res.data.toMs = res.data.points.back().ts;
            res.data.durationMs = res.data.toMs - res.data.fromMs;
        }

        ReplayData rd;
        rd.id = q.entityId;
        ReplayTrack track;
        track.id = q.entityId;
        track.label = q.label;
        track.kind = q.kind;
        track.color = q.color;
        for (const auto& p : res.data.points) {
            ReplaySample s = toSample(p);
            s.interpolated = (p.basis == "interpolated");
            track.samples.push_back(s);
            if (s.predicted) res.data.hasPredicted = true;
        }
        rd.tracks.push_back(track);
        res.data.replay = rd;

        res.code = 0;
        res.message = "ok";
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

// ============================================================================
// 保留策略（ELG-TRK-06）
// ============================================================================

RetentionResult EntityLedger::applyRetention(const RetentionInput& q) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RetentionResult res;
    const int64_t now = q.nowMs > 0 ? q.nowMs : st.nowLocked();
    res.ts = now;
    const int64_t maxAge = q.maxAgeMs > 0 ? q.maxAgeMs : st.def.track.retentionMaxAgeMs;
    const int maxPoints = q.maxPoints > 0 ? q.maxPoints : st.def.track.retentionMaxPoints;
    if (maxAge <= 0 && maxPoints <= 0) {
        res.code = 0;
        res.message = "retention disabled";
        return res;
    }
    for (auto& kv : st.missions) {
        if (!q.missionId.empty() && kv.first != q.missionId) continue;
        MissionState& m = kv.second;
        MissionState backup = m;
        bool touched = false;
        for (auto& tp : m.tracks) {
            if (!q.entityId.empty() && tp.first != q.entityId) continue;
            std::vector<TrackPoint>& pts = tp.second;
            if (pts.empty()) continue;
            touched = true;
            ++res.entities;
            if (maxAge > 0) {
                const int64_t cutoff = now - maxAge;
                const auto it = std::lower_bound(
                    pts.begin(), pts.end(), cutoff,
                    [](const TrackPoint& p, int64_t t) { return p.ts < t; });
                const int64_t n = static_cast<int64_t>(it - pts.begin());
                if (n > 0) {
                    pts.erase(pts.begin(), it);
                    res.removedByAge += n;
                    m.trackStats[tp.first].droppedByRetention += n;
                }
            }
            if (maxPoints > 0 && static_cast<int>(pts.size()) > maxPoints) {
                const int64_t n = static_cast<int64_t>(pts.size()) - maxPoints;
                pts.erase(pts.begin(), pts.begin() + static_cast<long>(n));
                res.removedByCap += n;
                m.trackStats[tp.first].droppedByCap += n;
            }
            TrackStats& s = m.trackStats[tp.first];
            s.points = static_cast<int>(pts.size());
            if (!pts.empty()) {
                s.oldestTs = pts.front().ts;
                s.newestTs = pts.back().ts;
            }
            res.remaining += static_cast<int64_t>(pts.size());
        }
        if (touched && !st.persistLocked(m)) {
            m = std::move(backup);
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
    }
    const int64_t dropped = res.removedByAge + res.removedByCap;
    st.metrics.retentionDropped += dropped;
    res.code = 0;
    res.message = dropped > 0 ? "cleaned" : "nothing-to-clean";
    return res;
}

}  // namespace entity_ledger
