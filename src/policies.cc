// entity-ledger · src/policies.cc —— 规则包装载与校验（protocol.md §5）
//
// 权威依据：
//   · protocol.md §5.1 文件骨架四字段 / §5.2 MAJOR 语义 / §5.3 kind 取值 /
//     §5.4 CTR-PL-01..08（逐条原因、未知字段忽略并计告警、缺必填拒绝、可导出）
//   · protocol.md §5.5 的 threatFactors（items + bands）与 entityTypes（items + numbering）骨架
//   · 需求专篇 ELG-REG-01/03/04/05/06、ELG-ID-01、ELG-RATE-01/03、ELG-RANK-01/03、
//     ELG-TRK-03/05/06、ELG-ACT-01/04/06、ELG-INTEL-03
//
// 设计：**只允许 §5.3 已冻结的两个 kind 归属本引擎**（entityTypes / threatFactors）。
// 其余规则内容（编号、动态状态、去重、置信度、旗标、视图、动作、关系、分档、窗口、排序、轨迹）
// 作为**顶层兄弟段**与 `items` 并列 —— 与 §5.5 `threatFactors` 的 `bands` 兄弟段、
// phase-engine `phases.json` 的 `progress/rollback/timeline` 兄弟段同惯例（见 D-PHE-01）。
// 装载可多次调用（先 entityTypes.json 再 threatFactors.json），**合并后**做一次整体语义校验，
// 失败 MUST 拒绝整包并逐条给出原因（CTR-PL-02），且保留上一次成功装载的规则。
#include "internal.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace entity_ledger {
namespace detail {

namespace {

const char* kKindEntityTypes = "entityTypes";
const char* kKindThreatFactors = "threatFactors";

// 引擎内建机制 token（**不是业务取值**：业务取值全部住在规则包）
const std::set<std::string>& factorSources() {
    static const std::set<std::string> s = {"typeBase", "distance",  "state",
                                            "confidence", "sourceCount", "attribute"};
    return s;
}
const std::set<std::string>& normalizeTypes() {
    static const std::set<std::string> s = {"percent", "range", "table", "identity"};
    return s;
}
const std::set<std::string>& directions() {
    static const std::set<std::string> s = {"higher", "lower"};
    return s;
}
const std::set<std::string>& missingPolicies() {
    static const std::set<std::string> s = {"skip", "zero", "reject"};
    return s;
}
const std::set<std::string>& dedupKeys() {
    static const std::set<std::string> s = {"obsKey", "typeKey", "space", "dynamicState"};
    return s;
}
const std::set<std::string>& rankFields() {
    static const std::set<std::string> s = {"priority", "threatScore", "threatBand",
                                            "confidence", "sourceCount", "no"};
    return s;
}
const std::set<std::string>& dedupModes() {
    static const std::set<std::string> s = {"conservative", "aggressive", "off"};
    return s;
}

struct Collector {
    std::vector<LoadIssue> issues;
    void add(const std::string& path, const std::string& field, const std::string& reason) {
        issues.push_back(LoadIssue{path, field, reason});
    }
};

bool isString(const json& j) { return j.is_string(); }

bool optBool(const json& obj, const char* key, bool def) {
    auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return def;
    return it->is_boolean() ? it->get<bool>() : def;
}

std::string optStr(const json& obj, const char* key, const std::string& def = "") {
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return def;
    return it->get<std::string>();
}

bool optNum(const json& obj, const char* key, double& out) {
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_number()) return false;
    out = it->get<double>();
    return true;
}

int64_t optInt(const json& obj, const char* key, int64_t def) {
    double v = 0.0;
    if (!optNum(obj, key, v)) return def;
    return static_cast<int64_t>(std::llround(v));
}

std::vector<std::string> stringArray(const json& obj, const char* key, Collector& c,
                                     const std::string& path) {
    std::vector<std::string> out;
    auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return out;
    if (!it->is_array()) {
        c.add(path, key, "must be an array of strings");
        return out;
    }
    for (std::size_t i = 0; i < it->size(); ++i) {
        const json& e = (*it)[i];
        if (!e.is_string() || e.get<std::string>().empty()) {
            c.add(path + "." + key + "[" + std::to_string(i) + "]", key,
                  "must be a non-empty string");
            continue;
        }
        out.push_back(e.get<std::string>());
    }
    return out;
}

std::string entryPath(const char* seg, std::size_t i, const char* field) {
    std::string p = std::string(seg) + "[" + std::to_string(i) + "]";
    if (field && *field) p += std::string(".") + field;
    return p;
}

/// `MAJOR.MINOR.PATCH` 解析；非法 → false
bool parseSchemaVersion(const std::string& s, int& major) {
    int a = 0, b = 0, cc = 0;
    char extra = 0;
    if (std::sscanf(s.c_str(), "%d.%d.%d%c", &a, &b, &cc, &extra) != 3) return false;
    if (a < 0 || b < 0 || cc < 0) return false;
    major = a;
    return true;
}

bool validGateId(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    if (!(id[0] >= 'a' && id[0] <= 'z')) return false;
    for (char ch : id) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-';
        if (!ok) return false;
    }
    return true;
}

}  // namespace

// ============================================================================
// Definition 查询辅助
// ============================================================================

const EntityType* Definition::findType(const std::string& key) const {
    auto it = types.find(key);
    return it == types.end() ? nullptr : &it->second;
}

const ActionDef* Definition::findAction(const std::string& key) const {
    auto it = actionIndex.find(key);
    return it == actionIndex.end() ? nullptr : &actions[it->second];
}

const ViewRule* Definition::findView(const std::string& key) const {
    auto it = viewIndex.find(key);
    return it == viewIndex.end() ? nullptr : &views[it->second];
}

const FlagDef* Definition::findFlag(const std::string& key) const {
    auto it = flagIndex.find(key);
    return it == flagIndex.end() ? nullptr : &flags[it->second];
}

const SourceDef* Definition::findSource(const std::string& key) const {
    auto it = confidence.sources.find(key);
    return it == confidence.sources.end() ? nullptr : &it->second;
}

const StrikePattern* Definition::findPattern(const std::string& key) const {
    for (const auto& p : window.patterns) {
        if (p.key == key) return &p;
    }
    return nullptr;
}

const EntityType* Definition::firstType() const {
    for (const auto& k : typeOrder) {
        const EntityType* t = findType(k);
        if (t) return t;
    }
    return nullptr;
}

const BandDef* Definition::bandFor(int score) const {
    for (const auto& b : bands) {
        if (score >= b.min) return &b;
    }
    return bands.empty() ? nullptr : &bands.back();
}

const PhaseFilterRule* Definition::filterFor(const ViewRule& v, const std::string& phaseKey) const {
    for (const auto& f : v.filters) {
        for (const auto& p : f.phases) {
            if (p == "*" || p == phaseKey) return &f;
        }
    }
    return nullptr;
}

std::string Definition::typeName(const std::string& typeKey) const {
    const EntityType* t = findType(typeKey);
    return t ? t->name : typeKey;  // MUST NOT 造文案
}

std::string Definition::viewName(const std::string& viewKey) const {
    const ViewRule* v = findView(viewKey);
    return v ? v->name : viewKey;
}

std::string Definition::actionName(const std::string& actionKey) const {
    const ActionDef* a = findAction(actionKey);
    return a ? a->name : actionKey;
}

bool Definition::hasState(const std::string& key) const {
    return std::find(states.keys.begin(), states.keys.end(), key) != states.keys.end();
}

bool Definition::transitionAllowed(const std::string& from, const std::string& to) const {
    if (states.anyTransition) return true;
    if (from == to) return true;
    for (const auto& t : states.transitions) {
        const bool fromOk = (t.first == "*" || t.first == from);
        const bool toOk = (t.second == "*" || t.second == to);
        if (fromOk && toOk) return true;
    }
    return false;
}

// ============================================================================
// digest / 规范化
// ============================================================================

std::string fnv1a64Hex(const std::string& bytes) {
    std::uint64_t h = 1469598103934665603ULL;  // FNV offset basis
    for (unsigned char c : bytes) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ULL;  // FNV prime
    }
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    return std::string(buf);
}

namespace {

void canonicalWrite(const json& v, std::string& out);

void canonicalObject(const json& v, std::string& out) {
    // 对象键 ASCII 升序（确定性；不依赖容器实现）
    std::vector<std::string> keys;
    keys.reserve(v.size());
    for (auto it = v.begin(); it != v.end(); ++it) keys.push_back(it.key());
    std::sort(keys.begin(), keys.end());
    out += "{";
    for (std::size_t i = 0; i < keys.size(); ++i) {
        if (i) out += ",";
        out += json(keys[i]).dump();
        out += ":";
        canonicalWrite(v[keys[i]], out);
    }
    out += "}";
}

void canonicalWrite(const json& v, std::string& out) {
    if (v.is_object()) {
        canonicalObject(v, out);
    } else if (v.is_array()) {
        out += "[";
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (i) out += ",";
            canonicalWrite(v[i], out);
        }
        out += "]";
    } else if (v.is_number_float()) {
        // 最短表示：整数不带 .0
        const double d = v.get<double>();
        if (d == std::floor(d) && std::fabs(d) < 1e15) {
            out += std::to_string(static_cast<long long>(d));
        } else {
            char buf[40];
            std::snprintf(buf, sizeof(buf), "%.17g", d);
            out += buf;
        }
    } else if (v.is_string()) {
        out += v.dump();
    } else if (v.is_boolean()) {
        out += v.get<bool>() ? "true" : "false";
    } else if (v.is_null()) {
        out += "null";
    } else {
        out += v.dump();
    }
}

}  // namespace

std::string canonicalBytes(const json& pkg) {
    std::string out;
    canonicalWrite(pkg, out);
    return out;
}

// ============================================================================
// 生效规则导出（CTR-PL-06；digest 的输入）
// ============================================================================

json definitionToJson(const Definition& def) {
    json out = json::object();
    out["policiesNamespace"] = def.ns;
    out["schemaVersion"] = def.schemaVersion;

    json et = json::object();
    json typeItems = json::array();
    for (const auto& k : def.typeOrder) {
        const EntityType* t = def.findType(k);
        if (!t) continue;
        json e = json::object();
        e["key"] = t->key;
        e["name"] = t->name;
        e["baseThreat"] = t->baseThreat;
        e["attributes"] = t->attributes;
        typeItems.push_back(e);
    }
    et["items"] = typeItems;
    json numbering = json::object();
    numbering["start"] = def.numbering.start;
    numbering["contiguous"] = def.numbering.contiguous;
    numbering["reuse"] = def.numbering.reuse;
    et["numbering"] = numbering;
    json geometry = json::object();
    geometry["formula"] = "haversine";
    geometry["earthRadiusM"] = def.earthRadiusM;
    et["geometry"] = geometry;
    if (def.referenceSet) {
        json r = json::object();
        r["lng"] = def.referenceLng;
        r["lat"] = def.referenceLat;
        et["reference"] = r;
    }

    json ds = json::object();
    json dsItems = json::array();
    for (const auto& k : def.states.keys) {
        json e = json::object();
        e["key"] = k;
        auto it = def.states.names.find(k);
        e["name"] = it == def.states.names.end() ? k : it->second;
        dsItems.push_back(e);
    }
    ds["items"] = dsItems;
    json trans = json::array();
    for (const auto& t : def.states.transitions) {
        json e = json::object();
        e["from"] = t.first;
        e["to"] = t.second;
        trans.push_back(e);
    }
    ds["transitions"] = trans;
    if (!def.states.defaultState.empty()) ds["default"] = def.states.defaultState;
    et["dynamicStates"] = ds;

    json dedup = json::object();
    dedup["mode"] = def.dedup.mode;
    dedup["keys"] = def.dedup.keys;
    dedup["requireTypeMatch"] = def.dedup.requireTypeMatch;
    dedup["spaceRadiusM"] = def.dedup.spaceRadiusM;
    dedup["timeWindowMs"] = def.dedup.timeWindowMs;
    dedup["allowManualSplit"] = def.dedup.allowManualSplit;
    dedup["onAmbiguous"] = def.dedup.onAmbiguous;
    et["dedup"] = dedup;

    json conf = json::object();
    conf["method"] = def.confidence.method;
    json srcs = json::array();
    for (const auto& k : def.confidence.sourceOrder) {
        const SourceDef* s = def.findSource(k);
        if (!s) continue;
        json e = json::object();
        e["key"] = s->key;
        e["name"] = s->name;
        e["weight"] = s->weight;
        srcs.push_back(e);
    }
    conf["sources"] = srcs;
    conf["multiSourceBonus"] = def.confidence.multiSourceBonus;
    conf["maxBonus"] = def.confidence.maxBonus;
    if (!def.confidence.defaultSource.empty()) conf["defaultSource"] = def.confidence.defaultSource;
    et["confidence"] = conf;

    json flags = json::array();
    for (const auto& f : def.flags) {
        json e = json::object();
        e["key"] = f.key;
        e["name"] = f.name;
        e["unique"] = f.unique;
        if (!f.exclusive.empty()) e["exclusive"] = f.exclusive;
        flags.push_back(e);
    }
    et["flags"] = flags;

    json views = json::array();
    for (const auto& v : def.views) {
        json e = json::object();
        e["key"] = v.key;
        e["name"] = v.name;
        json fs = json::array();
        for (const auto& f : v.filters) {
            json fe = json::object();
            fe["phases"] = f.phases;
            fe["includeTypes"] = f.includeTypes;
            fe["excludeTypes"] = f.excludeTypes;
            fe["requireFlags"] = f.requireFlags;
            fe["excludeFlags"] = f.excludeFlags;
            fe["minConfidence"] = f.minConfidence;
            fs.push_back(fe);
        }
        e["phaseFilters"] = fs;
        views.push_back(e);
    }
    et["views"] = views;

    json actions = json::array();
    for (const auto& a : def.actions) {
        json e = json::object();
        e["key"] = a.key;
        e["name"] = a.name;
        e["requires"] = a.requires;
        e["setsFlags"] = a.setsFlags;
        e["clearsFlags"] = a.clearsFlags;
        if (!a.setsDynamicState.empty()) e["setsDynamicState"] = a.setsDynamicState;
        e["reversible"] = a.reversible;
        e["exclusive"] = a.exclusive;
        e["once"] = a.once;
        e["undoWithinMs"] = a.undoWithinMs;
        e["setsPriority"] = a.setsPriority;
        e["priorityValue"] = a.priorityValue;
        e["addsToSequence"] = a.addsToSequence;
        actions.push_back(e);
    }
    et["actions"] = actions;

    json rel = json::object();
    json kinds = json::array();
    for (const auto& k : def.relations.kinds) {
        json e = json::object();
        e["key"] = k.key;
        e["name"] = k.name;
        e["cyclic"] = k.cyclic;
        kinds.push_back(e);
    }
    rel["kinds"] = kinds;
    json rss = json::array();
    for (const auto& s : def.relations.states) {
        json e = json::object();
        e["key"] = s.key;
        e["name"] = s.name;
        rss.push_back(e);
    }
    rel["states"] = rss;
    rel["default"] = def.relations.defaultState;
    et["relations"] = rel;

    out["entityTypes"] = et;

    json tf = json::object();
    json factors = json::array();
    for (const auto& f : def.factors) {
        json e = json::object();
        e["key"] = f.key;
        e["name"] = f.name;
        e["source"] = f.source;
        if (!f.attributeKey.empty()) e["attribute"] = f.attributeKey;
        e["weight"] = f.weight;
        json n = json::object();
        n["type"] = f.normalizeType;
        if (f.normalizeType == "range") {
            n["min"] = f.normMin;
            n["max"] = f.normMax;
        }
        if (f.normalizeType == "table") {
            json table = json::object();
            for (const auto& kv : f.table) table[kv.first] = kv.second;
            n["table"] = table;
        }
        e["normalize"] = n;
        e["direction"] = f.direction;
        e["missing"] = f.missing;
        factors.push_back(e);
    }
    tf["items"] = factors;
    json bands = json::array();
    for (const auto& b : def.bands) {
        json e = json::object();
        e["key"] = b.key;
        e["min"] = b.min;
        if (!b.state.empty()) e["state"] = b.state;
        bands.push_back(e);
    }
    tf["bands"] = bands;

    json sw = json::object();
    sw["horizonMs"] = def.window.horizonMs;
    sw["stepMs"] = def.window.stepMs;
    sw["minDurationMs"] = def.window.minDurationMs;
    sw["minPoints"] = def.window.minPoints;
    json pats = json::array();
    for (const auto& p : def.window.patterns) {
        json e = json::object();
        e["key"] = p.key;
        e["appliesToTypes"] = p.appliesToTypes;
        e["cycleMs"] = p.cycleMs;
        e["exposedMs"] = p.exposedMs;
        e["offsetMs"] = p.offsetMs;
        pats.push_back(e);
    }
    sw["patterns"] = pats;
    tf["strikeWindow"] = sw;

    json rank = json::object();
    json rk = json::array();
    for (const auto& k : def.rank.keys) {
        json e = json::object();
        e["field"] = k.field;
        e["direction"] = k.direction;
        rk.push_back(e);
    }
    rank["keys"] = rk;
    rank["defaultPriority"] = def.rank.defaultPriority;
    rank["sequenceLimit"] = def.rank.sequenceLimit;
    tf["rank"] = rank;

    json track = json::object();
    track["maxPointsPerEntity"] = def.track.maxPointsPerEntity;
    json retention = json::object();
    retention["maxAgeMs"] = def.track.retentionMaxAgeMs;
    retention["maxPoints"] = def.track.retentionMaxPoints;
    track["retention"] = retention;
    json dec = json::object();
    dec["everyNth"] = def.track.decimateEveryNth;
    dec["minIntervalMs"] = def.track.decimateMinIntervalMs;
    track["decimate"] = dec;
    json pred = json::object();
    pred["horizonMs"] = def.track.predictHorizonMs;
    pred["stepMs"] = def.track.predictStepMs;
    pred["minPoints"] = def.track.predictMinPoints;
    pred["maxPoints"] = def.track.predictMaxPoints;
    track["predict"] = pred;
    json tl = json::object();
    tl["stepMs"] = def.track.timelineStepMs;
    tl["includePredicted"] = def.track.timelineIncludePredicted;
    track["timeline"] = tl;
    tf["trajectory"] = track;

    out["threatFactors"] = tf;
    return out;
}

// ============================================================================
// 装载校验
// ============================================================================

namespace {

void collectUnknown(const json& obj, const std::set<std::string>& known, Definition& def,
                    const std::string& prefix) {
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (known.count(it.key())) continue;
        def.warnings.push_back("unknown field ignored: " + prefix + it.key());
        ++def.unknownFields;
    }
}

/// items[]：实体类型
void parseEntityTypes(const json& items, Collector& c, Definition& def) {
    for (std::size_t i = 0; i < items.size(); ++i) {
        const json& e = items[i];
        const std::string p = entryPath("items", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        EntityType t;
        t.key = optStr(e, "key");
        t.name = optStr(e, "name");
        double base = 0.0;
        const bool hasBase = optNum(e, "baseThreat", base);
        if (t.key.empty()) c.add(p, "key", "missing required field (non-empty string)");
        if (t.name.empty()) c.add(p, "name", "missing required field (non-empty string)");
        if (!hasBase) {
            c.add(p, "baseThreat", "missing required field (number)");
        } else if (base < 0.0 || base > 1.0) {
            c.add(p, "baseThreat", "must be within [0,1]");
        }
        auto ait = e.find("attributes");
        if (ait != e.end() && !ait->is_null()) {
            if (!ait->is_object()) c.add(p, "attributes", "must be an object");
            else t.attributes = *ait;
        }
        const std::set<std::string> known = {"key", "name", "baseThreat", "attributes"};
        collectUnknown(e, known, def, p + ".");
        if (t.key.empty()) continue;
        if (def.types.count(t.key)) {
            c.add(p, "key", "duplicate entity type key: " + t.key);
            continue;
        }
        t.baseThreat = hasBase ? base : 0.0;
        def.typeOrder.push_back(t.key);
        def.types.emplace(t.key, t);
    }
}

/// items[]：评级因子
void parseFactors(const json& items, Collector& c, Definition& def) {
    for (std::size_t i = 0; i < items.size(); ++i) {
        const json& e = items[i];
        const std::string p = entryPath("items", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        FactorDef f;
        f.key = optStr(e, "key");
        f.name = optStr(e, "name");
        f.source = optStr(e, "source");
        double w = 0.0;
        const bool hasW = optNum(e, "weight", w);
        if (f.key.empty()) c.add(p, "key", "missing required field (non-empty string)");
        if (f.name.empty()) c.add(p, "name", "missing required field (non-empty string)");
        if (f.source.empty()) {
            c.add(p, "source", "missing required field (mechanism token)");
        } else if (!factorSources().count(f.source)) {
            c.add(p, "source", "unknown mechanism token: " + f.source);
        }
        if (!hasW) {
            c.add(p, "weight", "missing required field (number)");
        } else if (w < 0.0) {
            c.add(p, "weight", "must be >= 0");
        }
        f.attributeKey = optStr(e, "attribute");
        if (f.source == "attribute" && f.attributeKey.empty()) {
            c.add(p, "attribute", "required when source = attribute");
        }
        f.direction = optStr(e, "direction", "higher");
        if (!directions().count(f.direction)) {
            c.add(p, "direction", "must be one of: higher / lower");
        }
        f.missing = optStr(e, "missing", "zero");
        if (!missingPolicies().count(f.missing)) {
            c.add(p, "missing", "must be one of: skip / zero / reject");
        }
        auto nit = e.find("normalize");
        if (nit == e.end() || !nit->is_object()) {
            c.add(p, "normalize", "missing required field (object)");
        } else {
            const json& n = *nit;
            f.normalizeType = optStr(n, "type");
            if (!normalizeTypes().count(f.normalizeType)) {
                c.add(p, "normalize.type", "must be one of: percent / range / table / identity");
            }
            if (f.normalizeType == "range") {
                double mn = 0.0, mx = 0.0;
                const bool hm = optNum(n, "min", mn);
                const bool hx = optNum(n, "max", mx);
                if (!hm) c.add(p, "normalize.min", "required for range normalization");
                if (!hx) c.add(p, "normalize.max", "required for range normalization");
                if (hm && hx && !(mx > mn)) c.add(p, "normalize.max", "must be greater than min");
                f.normMin = mn;
                f.normMax = mx;
            }
            if (f.normalizeType == "table") {
                auto tit = n.find("table");
                if (tit == n.end() || !tit->is_object() || tit->empty()) {
                    c.add(p, "normalize.table", "required non-empty object for table normalization");
                } else {
                    for (auto kv = tit->begin(); kv != tit->end(); ++kv) {
                        if (!kv.value().is_number()) {
                            c.add(p, "normalize.table." + kv.key(), "must be a number");
                            continue;
                        }
                        f.table[kv.key()] = kv.value().get<double>();
                    }
                }
            }
            const std::set<std::string> nknown = {"type", "min", "max", "table"};
            collectUnknown(n, nknown, def, p + ".normalize.");
        }
        const std::set<std::string> known = {"key",   "name",     "source", "attribute",
                                             "weight", "normalize", "direction", "missing"};
        collectUnknown(e, known, def, p + ".");
        if (f.key.empty() || !hasW) continue;
        bool dup = false;
        for (const auto& prev : def.factors) {
            if (prev.key == f.key) dup = true;
        }
        if (dup) {
            c.add(p, "key", "duplicate factor key: " + f.key);
            continue;
        }
        f.weight = w;
        f.weightPpm = static_cast<int64_t>(std::llround(w * 1000000.0));
        def.factors.push_back(f);
        def.totalWeightPpm += f.weightPpm;
    }
}

void parseBands(const json& bands, Collector& c, Definition& def) {
    if (!bands.is_array()) {
        c.add("bands", "bands", "must be an array");
        return;
    }
    def.bands.clear();
    for (std::size_t i = 0; i < bands.size(); ++i) {
        const json& e = bands[i];
        const std::string p = entryPath("bands", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        BandDef b;
        b.key = optStr(e, "key");
        double mn = 0.0;
        const bool hmin = optNum(e, "min", mn);
        b.state = optStr(e, "state");
        if (b.key.empty()) c.add(p, "key", "missing required field (non-empty string)");
        if (!hmin) c.add(p, "min", "missing required field (number)");
        const std::set<std::string> known = {"key", "min", "state"};
        collectUnknown(e, known, def, p + ".");
        if (b.key.empty() || !hmin) continue;
        for (const auto& prev : def.bands) {
            if (prev.key == b.key) c.add(p, "key", "duplicate band key: " + b.key);
        }
        b.min = static_cast<int>(std::llround(mn));
        if (b.state.empty()) b.state = b.key;  // CTR-PL-04 缺省：未声明 state 时回落 band key
        def.bands.push_back(b);
    }
    // 降序 + 覆盖 0（否则任何 score 都可能无档可落）
    std::stable_sort(def.bands.begin(), def.bands.end(),
                     [](const BandDef& a, const BandDef& b) { return a.min > b.min; });
    if (!def.bands.empty()) {
        bool coversZero = false;
        for (const auto& b : def.bands) {
            if (b.min <= 0) coversZero = true;
        }
        if (!coversZero) c.add("bands", "min", "at least one band must have min <= 0");
    }
}

void parseWindow(const json& sw, Collector& c, Definition& def) {
    if (!sw.is_object()) {
        c.add("strikeWindow", "strikeWindow", "must be an object");
        return;
    }
    StrikeWindowRule r = def.window;
    double v = 0.0;
    if (optNum(sw, "horizonMs", v)) r.horizonMs = static_cast<int64_t>(std::llround(v));
    if (optNum(sw, "stepMs", v)) r.stepMs = static_cast<int64_t>(std::llround(v));
    if (optNum(sw, "minDurationMs", v)) r.minDurationMs = static_cast<int64_t>(std::llround(v));
    if (optNum(sw, "minPoints", v)) r.minPoints = static_cast<int>(std::llround(v));
    if (r.horizonMs <= 0) c.add("strikeWindow", "horizonMs", "must be > 0");
    if (r.stepMs <= 0) c.add("strikeWindow", "stepMs", "must be > 0");
    if (r.minPoints < 2) c.add("strikeWindow", "minPoints", "must be >= 2");
    auto pit = sw.find("patterns");
    if (pit != sw.end() && !pit->is_null()) {
        if (!pit->is_array()) {
            c.add("strikeWindow", "patterns", "must be an array");
        } else {
            r.patterns.clear();
            for (std::size_t i = 0; i < pit->size(); ++i) {
                const json& e = (*pit)[i];
                const std::string p = entryPath("strikeWindow.patterns", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                StrikePattern sp;
                sp.key = optStr(e, "key");
                sp.appliesToTypes = stringArray(e, "appliesToTypes", c, p);
                double cy = 0.0, ex = 0.0, off = 0.0;
                const bool hc = optNum(e, "cycleMs", cy);
                const bool he = optNum(e, "exposedMs", ex);
                const bool ho = optNum(e, "offsetMs", off);
                if (sp.key.empty()) c.add(p, "key", "missing required field (non-empty string)");
                if (!hc) c.add(p, "cycleMs", "missing required field (number)");
                if (!he) c.add(p, "exposedMs", "missing required field (number)");
                if (!ho) c.add(p, "offsetMs", "missing required field (number)");
                sp.cycleMs = static_cast<int64_t>(std::llround(cy));
                sp.exposedMs = static_cast<int64_t>(std::llround(ex));
                sp.offsetMs = static_cast<int64_t>(std::llround(off));
                if (sp.cycleMs <= 0) c.add(p, "cycleMs", "must be > 0");
                if (sp.exposedMs <= 0) c.add(p, "exposedMs", "must be > 0");
                if (sp.exposedMs > sp.cycleMs) c.add(p, "exposedMs", "must be <= cycleMs");
                if (sp.offsetMs < 0) c.add(p, "offsetMs", "must be >= 0");
                if (sp.appliesToTypes.empty()) sp.appliesToTypes.push_back("*");
                const std::set<std::string> known = {"key", "appliesToTypes", "cycleMs",
                                                     "exposedMs", "offsetMs"};
                collectUnknown(e, known, def, p + ".");
                if (!sp.key.empty()) r.patterns.push_back(sp);
            }
        }
    }
    const std::set<std::string> known = {"horizonMs", "stepMs", "minDurationMs", "minPoints",
                                         "patterns"};
    collectUnknown(sw, known, def, "strikeWindow.");
    def.window = r;
}

void parseRank(const json& rk, Collector& c, Definition& def) {
    if (!rk.is_object()) {
        c.add("rank", "rank", "must be an object");
        return;
    }
    RankRule r = def.rank;
    auto kit = rk.find("keys");
    if (kit != rk.end() && !kit->is_null()) {
        if (!kit->is_array() || kit->empty()) {
            c.add("rank", "keys", "must be a non-empty array");
        } else {
            r.keys.clear();
            for (std::size_t i = 0; i < kit->size(); ++i) {
                const json& e = (*kit)[i];
                const std::string p = entryPath("rank.keys", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                RankKeyDef k;
                k.field = optStr(e, "field");
                k.direction = optStr(e, "direction", "asc");
                if (!rankFields().count(k.field)) {
                    c.add(p, "field", "unknown sort field: " + k.field);
                }
                if (k.direction != "asc" && k.direction != "desc") {
                    c.add(p, "direction", "must be asc or desc");
                }
                if (rankFields().count(k.field) &&
                    (k.direction == "asc" || k.direction == "desc")) {
                    r.keys.push_back(k);
                }
            }
        }
    }
    double v = 0.0;
    if (optNum(rk, "defaultPriority", v)) r.defaultPriority = static_cast<int>(std::llround(v));
    if (optNum(rk, "sequenceLimit", v)) r.sequenceLimit = static_cast<int>(std::llround(v));
    if (r.sequenceLimit < 0) c.add("rank", "sequenceLimit", "must be >= 0");
    const std::set<std::string> known = {"keys", "defaultPriority", "sequenceLimit"};
    collectUnknown(rk, known, def, "rank.");
    def.rank = r;
}

void parseTrack(const json& tk, Collector& c, Definition& def) {
    if (!tk.is_object()) {
        c.add("trajectory", "trajectory", "must be an object");
        return;
    }
    TrackRule r = def.track;
    double v = 0.0;
    if (optNum(tk, "maxPointsPerEntity", v)) r.maxPointsPerEntity = static_cast<int>(v);
    auto rit = tk.find("retention");
    if (rit != tk.end() && rit->is_object()) {
        if (optNum(*rit, "maxAgeMs", v)) r.retentionMaxAgeMs = static_cast<int64_t>(v);
        if (optNum(*rit, "maxPoints", v)) r.retentionMaxPoints = static_cast<int>(v);
        const std::set<std::string> known = {"maxAgeMs", "maxPoints"};
        collectUnknown(*rit, known, def, "trajectory.retention.");
    }
    auto dit = tk.find("decimate");
    if (dit != tk.end() && dit->is_object()) {
        if (optNum(*dit, "everyNth", v)) r.decimateEveryNth = static_cast<int>(v);
        if (optNum(*dit, "minIntervalMs", v)) r.decimateMinIntervalMs = static_cast<int64_t>(v);
        const std::set<std::string> known = {"everyNth", "minIntervalMs"};
        collectUnknown(*dit, known, def, "trajectory.decimate.");
    }
    auto pit = tk.find("predict");
    if (pit != tk.end() && pit->is_object()) {
        if (optNum(*pit, "horizonMs", v)) r.predictHorizonMs = static_cast<int64_t>(v);
        if (optNum(*pit, "stepMs", v)) r.predictStepMs = static_cast<int64_t>(v);
        if (optNum(*pit, "minPoints", v)) r.predictMinPoints = static_cast<int>(v);
        if (optNum(*pit, "maxPoints", v)) r.predictMaxPoints = static_cast<int>(v);
        const std::set<std::string> known = {"horizonMs", "stepMs", "minPoints", "maxPoints"};
        collectUnknown(*pit, known, def, "trajectory.predict.");
    }
    auto tit = tk.find("timeline");
    if (tit != tk.end() && tit->is_object()) {
        if (optNum(*tit, "stepMs", v)) r.timelineStepMs = static_cast<int64_t>(v);
        r.timelineIncludePredicted = optBool(*tit, "includePredicted", r.timelineIncludePredicted);
        const std::set<std::string> known = {"stepMs", "includePredicted"};
        collectUnknown(*tit, known, def, "trajectory.timeline.");
    }
    if (r.decimateEveryNth < 1) c.add("trajectory", "decimate.everyNth", "must be >= 1");
    if (r.predictStepMs <= 0) c.add("trajectory", "predict.stepMs", "must be > 0");
    if (r.predictMinPoints < 2) c.add("trajectory", "predict.minPoints", "must be >= 2");
    const std::set<std::string> known = {"maxPointsPerEntity", "retention", "decimate", "predict",
                                         "timeline"};
    collectUnknown(tk, known, def, "trajectory.");
    def.track = r;
}

void parseNumbering(const json& nb, Collector& c, Definition& def) {
    if (!nb.is_object()) {
        c.add("numbering", "numbering", "must be an object");
        return;
    }
    double v = 0.0;
    if (optNum(nb, "start", v)) def.numbering.start = static_cast<int>(std::llround(v));
    def.numbering.contiguous = optBool(nb, "contiguous", def.numbering.contiguous);
    def.numbering.reuse = optBool(nb, "reuse", def.numbering.reuse);
    if (def.numbering.start < 0) c.add("numbering", "start", "must be >= 0");
    const std::set<std::string> known = {"start", "contiguous", "reuse"};
    collectUnknown(nb, known, def, "numbering.");
}

void parseGeometry(const json& g, Collector& c, Definition& def) {
    if (!g.is_object()) {
        c.add("geometry", "geometry", "must be an object");
        return;
    }
    const std::string formula = optStr(g, "formula", "haversine");
    if (formula != "haversine") c.add("geometry", "formula", "unsupported formula: " + formula);
    double v = 0.0;
    if (optNum(g, "earthRadiusM", v)) {
        if (v <= 0) c.add("geometry", "earthRadiusM", "must be > 0");
        else def.earthRadiusM = v;
    }
    const std::set<std::string> known = {"formula", "earthRadiusM"};
    collectUnknown(g, known, def, "geometry.");
}

void parseReference(const json& rf, Collector& c, Definition& def) {
    if (!rf.is_object()) {
        c.add("reference", "reference", "must be an object");
        return;
    }
    double lng = 0.0, lat = 0.0;
    const bool hl = optNum(rf, "lng", lng);
    const bool ha = optNum(rf, "lat", lat);
    if (!hl) c.add("reference", "lng", "missing required field (number)");
    if (!ha) c.add("reference", "lat", "missing required field (number)");
    if (hl && ha) {
        def.referenceSet = true;
        def.referenceLng = lng;
        def.referenceLat = lat;
    }
    const std::set<std::string> known = {"lng", "lat"};
    collectUnknown(rf, known, def, "reference.");
}

void parseDynamicStates(const json& ds, Collector& c, Definition& def) {
    if (!ds.is_object()) {
        c.add("dynamicStates", "dynamicStates", "must be an object");
        return;
    }
    auto iit = ds.find("items");
    if (iit == ds.end() || !iit->is_array()) {
        c.add("dynamicStates", "items", "missing required field (array)");
    } else {
        def.states.keys.clear();
        def.states.names.clear();
        for (std::size_t i = 0; i < iit->size(); ++i) {
            const json& e = (*iit)[i];
            const std::string p = entryPath("dynamicStates.items", i, "");
            if (!e.is_object()) {
                c.add(p, "", "must be an object");
                continue;
            }
            const std::string k = optStr(e, "key");
            if (k.empty()) {
                c.add(p, "key", "missing required field (non-empty string)");
                continue;
            }
            if (def.states.names.count(k)) {
                c.add(p, "key", "duplicate state key: " + k);
                continue;
            }
            def.states.keys.push_back(k);
            def.states.names[k] = optStr(e, "name", k);
            const std::set<std::string> known = {"key", "name"};
            collectUnknown(e, known, def, p + ".");
        }
    }
    auto tit = ds.find("transitions");
    if (tit != ds.end() && !tit->is_null()) {
        if (!tit->is_array()) {
            c.add("dynamicStates", "transitions", "must be an array");
        } else {
            def.states.transitions.clear();
            for (std::size_t i = 0; i < tit->size(); ++i) {
                const json& e = (*tit)[i];
                const std::string p = entryPath("dynamicStates.transitions", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                const std::string from = optStr(e, "from");
                const std::string to = optStr(e, "to");
                if (from.empty()) c.add(p, "from", "missing required field (non-empty string)");
                if (to.empty()) c.add(p, "to", "missing required field (non-empty string)");
                if (!from.empty() && !to.empty()) def.states.transitions.emplace_back(from, to);
            }
            def.states.anyTransition = def.states.transitions.empty();
        }
    }
    const std::string defState = optStr(ds, "default");
    if (!defState.empty()) def.states.defaultState = defState;
    if (def.states.defaultState.empty() && !def.states.keys.empty()) {
        def.states.defaultState = def.states.keys.front();
    }
    const std::set<std::string> known = {"items", "transitions", "default"};
    collectUnknown(ds, known, def, "dynamicStates.");
}

void parseDedup(const json& dd, Collector& c, Definition& def) {
    if (!dd.is_object()) {
        c.add("dedup", "dedup", "must be an object");
        return;
    }
    const std::string mode = optStr(dd, "mode", def.dedup.mode);
    if (!dedupModes().count(mode)) {
        c.add("dedup", "mode", "must be one of: conservative / aggressive / off");
    } else {
        def.dedup.mode = mode;
    }
    auto kit = dd.find("keys");
    if (kit != dd.end() && !kit->is_null()) {
        if (!kit->is_array()) {
            c.add("dedup", "keys", "must be an array");
        } else {
            def.dedup.keys.clear();
            for (std::size_t i = 0; i < kit->size(); ++i) {
                const json& e = (*kit)[i];
                const std::string p = entryPath("dedup.keys", i, "");
                if (!e.is_string()) {
                    c.add(p, "", "must be a string");
                    continue;
                }
                const std::string k = e.get<std::string>();
                if (!dedupKeys().count(k)) {
                    c.add(p, "", "unknown dedup key: " + k);
                    continue;
                }
                def.dedup.keys.push_back(k);
            }
        }
    }
    def.dedup.requireTypeMatch = optBool(dd, "requireTypeMatch", def.dedup.requireTypeMatch);
    def.dedup.allowManualSplit = optBool(dd, "allowManualSplit", def.dedup.allowManualSplit);
    double v = 0.0;
    if (optNum(dd, "spaceRadiusM", v)) def.dedup.spaceRadiusM = static_cast<int64_t>(std::llround(v));
    if (optNum(dd, "timeWindowMs", v)) def.dedup.timeWindowMs = static_cast<int64_t>(std::llround(v));
    const std::string onAmb = optStr(dd, "onAmbiguous", def.dedup.onAmbiguous);
    if (onAmb != "separate" && onAmb != "merge") {
        c.add("dedup", "onAmbiguous", "must be one of: separate / merge");
    } else {
        def.dedup.onAmbiguous = onAmb;
    }
    if (def.dedup.mode == "off") def.dedup.keys.clear();
    const std::set<std::string> known = {"mode",   "keys",         "requireTypeMatch",
                                         "spaceRadiusM", "timeWindowMs", "allowManualSplit",
                                         "onAmbiguous"};
    collectUnknown(dd, known, def, "dedup.");
}

void parseConfidence(const json& cf, Collector& c, Definition& def) {
    if (!cf.is_object()) {
        c.add("confidence", "confidence", "must be an object");
        return;
    }
    const std::string method = optStr(cf, "method", def.confidence.method);
    if (method != "weighted-mean" && method != "max") {
        c.add("confidence", "method", "must be one of: weighted-mean / max");
    } else {
        def.confidence.method = method;
    }
    auto sit = cf.find("sources");
    if (sit != cf.end() && !sit->is_null()) {
        if (!sit->is_array()) {
            c.add("confidence", "sources", "must be an array");
        } else {
            def.confidence.sources.clear();
            def.confidence.sourceOrder.clear();
            for (std::size_t i = 0; i < sit->size(); ++i) {
                const json& e = (*sit)[i];
                const std::string p = entryPath("confidence.sources", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                SourceDef s;
                s.key = optStr(e, "key");
                s.name = optStr(e, "name", s.key);
                double w = 1.0;
                if (!optNum(e, "weight", w)) w = 1.0;
                if (s.key.empty()) {
                    c.add(p, "key", "missing required field (non-empty string)");
                    continue;
                }
                if (def.confidence.sources.count(s.key)) {
                    c.add(p, "key", "duplicate source key: " + s.key);
                    continue;
                }
                if (w < 0) {
                    c.add(p, "weight", "must be >= 0");
                    continue;
                }
                s.weight = w;
                s.weightPpm = static_cast<int64_t>(std::llround(w * 1000000.0));
                def.confidence.sources.emplace(s.key, s);
                def.confidence.sourceOrder.push_back(s.key);
            }
        }
    }
    double v = 0.0;
    if (optNum(cf, "multiSourceBonus", v)) def.confidence.multiSourceBonus = v;
    if (optNum(cf, "maxBonus", v)) def.confidence.maxBonus = v;
    const std::string dst = optStr(cf, "defaultSource");
    if (!dst.empty()) def.confidence.defaultSource = dst;
    if (def.confidence.defaultSource.empty() && !def.confidence.sourceOrder.empty()) {
        def.confidence.defaultSource = def.confidence.sourceOrder.front();
    }
    const std::set<std::string> known = {"method", "sources", "multiSourceBonus", "maxBonus",
                                         "defaultSource"};
    collectUnknown(cf, known, def, "confidence.");
}

void parseFlags(const json& fl, Collector& c, Definition& def) {
    if (!fl.is_array()) {
        c.add("flags", "flags", "must be an array");
        return;
    }
    def.flags.clear();
    def.flagIndex.clear();
    for (std::size_t i = 0; i < fl.size(); ++i) {
        const json& e = fl[i];
        const std::string p = entryPath("flags", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        FlagDef f;
        f.key = optStr(e, "key");
        f.name = optStr(e, "name", f.key);
        f.unique = optBool(e, "unique", false);
        f.exclusive = stringArray(e, "exclusive", c, p);
        if (f.key.empty()) {
            c.add(p, "key", "missing required field (non-empty string)");
            continue;
        }
        if (def.flagIndex.count(f.key)) {
            c.add(p, "key", "duplicate flag key: " + f.key);
            continue;
        }
        const std::set<std::string> known = {"key", "name", "unique", "exclusive"};
        collectUnknown(e, known, def, p + ".");
        def.flagIndex[f.key] = def.flags.size();
        def.flags.push_back(f);
    }
}

void parseViews(const json& vs, Collector& c, Definition& def) {
    if (!vs.is_array()) {
        c.add("views", "views", "must be an array");
        return;
    }
    def.views.clear();
    def.viewIndex.clear();
    for (std::size_t i = 0; i < vs.size(); ++i) {
        const json& e = vs[i];
        const std::string p = entryPath("views", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        ViewRule v;
        v.key = optStr(e, "key");
        v.name = optStr(e, "name", v.key);
        if (v.key.empty()) {
            c.add(p, "key", "missing required field (non-empty string)");
            continue;
        }
        auto fit = e.find("phaseFilters");
        if (fit != e.end() && !fit->is_null()) {
            if (!fit->is_array() || fit->empty()) {
                c.add(p, "phaseFilters", "must be a non-empty array");
            } else {
                for (std::size_t j = 0; j < fit->size(); ++j) {
                    const json& fe = (*fit)[j];
                    const std::string fp = entryPath("views", i, "phaseFilters") + "[" +
                                           std::to_string(j) + "]";
                    if (!fe.is_object()) {
                        c.add(fp, "", "must be an object");
                        continue;
                    }
                    PhaseFilterRule f;
                    f.phases = stringArray(fe, "phases", c, fp);
                    if (f.phases.empty()) f.phases.push_back("*");
                    f.includeTypes = stringArray(fe, "includeTypes", c, fp);
                    f.excludeTypes = stringArray(fe, "excludeTypes", c, fp);
                    f.requireFlags = stringArray(fe, "requireFlags", c, fp);
                    f.excludeFlags = stringArray(fe, "excludeFlags", c, fp);
                    double mc = 0.0;
                    if (optNum(fe, "minConfidence", mc)) {
                        if (mc < 0.0 || mc > 1.0) {
                            c.add(fp, "minConfidence", "must be within [0,1]");
                        } else {
                            f.minConfidence = mc;
                        }
                    }
                    const std::set<std::string> fknown = {"phases",      "includeTypes",
                                                          "excludeTypes", "requireFlags",
                                                          "excludeFlags", "minConfidence"};
                    collectUnknown(fe, fknown, def, fp + ".");
                    v.filters.push_back(f);
                }
            }
        }
        if (v.filters.empty()) {
            PhaseFilterRule f;
            f.phases.push_back("*");
            v.filters.push_back(f);
        }
        const std::set<std::string> known = {"key", "name", "phaseFilters"};
        collectUnknown(e, known, def, p + ".");
        if (def.viewIndex.count(v.key)) {
            c.add(p, "key", "duplicate view key: " + v.key);
            continue;
        }
        def.viewIndex[v.key] = def.views.size();
        def.views.push_back(v);
    }
}

void parseActions(const json& ac, Collector& c, Definition& def) {
    if (!ac.is_array()) {
        c.add("actions", "actions", "must be an array");
        return;
    }
    def.actions.clear();
    def.actionIndex.clear();
    for (std::size_t i = 0; i < ac.size(); ++i) {
        const json& e = ac[i];
        const std::string p = entryPath("actions", i, "");
        if (!e.is_object()) {
            c.add(p, "", "must be an object");
            continue;
        }
        ActionDef a;
        a.key = optStr(e, "key");
        a.name = optStr(e, "name", a.key);
        a.requires = stringArray(e, "requires", c, p);
        a.setsFlags = stringArray(e, "setsFlags", c, p);
        a.clearsFlags = stringArray(e, "clearsFlags", c, p);
        a.setsDynamicState = optStr(e, "setsDynamicState");
        a.reversible = optBool(e, "reversible", true);
        a.exclusive = optBool(e, "exclusive", false);
        a.once = optBool(e, "once", true);
        a.setsPriority = optBool(e, "setsPriority", false);
        a.addsToSequence = optBool(e, "addsToSequence", false);
        double v = 0.0;
        if (optNum(e, "undoWithinMs", v)) a.undoWithinMs = static_cast<int64_t>(std::llround(v));
        if (optNum(e, "priorityValue", v)) a.priorityValue = static_cast<int>(std::llround(v));
        if (a.key.empty()) {
            c.add(p, "key", "missing required field (non-empty string)");
            continue;
        }
        for (std::size_t j = 0; j < a.requires.size(); ++j) {
            const std::string& g = a.requires[j];
            if (isBuiltinGate(g)) continue;
            if (!validGateId(g)) {
                c.add(p + ".requires[" + std::to_string(j) + "]", "requires",
                      "host gate id must match ^[a-z][a-z0-9-]{0,63}$ (builtin gates start with '$')");
            }
        }
        const std::set<std::string> known = {"key",       "name",       "requires",
                                             "setsFlags", "clearsFlags", "setsDynamicState",
                                             "reversible", "exclusive",  "once",
                                             "undoWithinMs", "setsPriority", "priorityValue",
                                             "addsToSequence"};
        collectUnknown(e, known, def, p + ".");
        if (def.actionIndex.count(a.key)) {
            c.add(p, "key", "duplicate action key: " + a.key);
            continue;
        }
        def.actionIndex[a.key] = def.actions.size();
        def.actions.push_back(a);
    }
}

void parseRelations(const json& rl, Collector& c, Definition& def) {
    if (!rl.is_object()) {
        c.add("relations", "relations", "must be an object");
        return;
    }
    auto kit = rl.find("kinds");
    if (kit != rl.end() && !kit->is_null()) {
        if (!kit->is_array()) {
            c.add("relations", "kinds", "must be an array");
        } else {
            def.relations.kinds.clear();
            for (std::size_t i = 0; i < kit->size(); ++i) {
                const json& e = (*kit)[i];
                const std::string p = entryPath("relations.kinds", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                RelationDef d;
                d.key = optStr(e, "key");
                d.name = optStr(e, "name", d.key);
                d.cyclic = optBool(e, "cyclic", false);
                if (d.key.empty()) {
                    c.add(p, "key", "missing required field (non-empty string)");
                    continue;
                }
                for (const auto& prev : def.relations.kinds) {
                    if (prev.key == d.key) c.add(p, "key", "duplicate kind key: " + d.key);
                }
                const std::set<std::string> known = {"key", "name", "cyclic"};
                collectUnknown(e, known, def, p + ".");
                def.relations.kinds.push_back(d);
            }
        }
    }
    auto sit = rl.find("states");
    if (sit != rl.end() && !sit->is_null()) {
        if (!sit->is_array()) {
            c.add("relations", "states", "must be an array");
        } else {
            def.relations.states.clear();
            for (std::size_t i = 0; i < sit->size(); ++i) {
                const json& e = (*sit)[i];
                const std::string p = entryPath("relations.states", i, "");
                if (!e.is_object()) {
                    c.add(p, "", "must be an object");
                    continue;
                }
                RelationStateDef s;
                s.key = optStr(e, "key");
                s.name = optStr(e, "name", s.key);
                if (s.key.empty()) {
                    c.add(p, "key", "missing required field (non-empty string)");
                    continue;
                }
                def.relations.states.push_back(s);
            }
            if (!def.relations.states.empty()) {
                def.relations.defaultState = def.relations.states.front().key;
            }
        }
    }
    const std::string dst = optStr(rl, "default");
    if (!dst.empty()) def.relations.defaultState = dst;
    const std::set<std::string> known = {"kinds", "states", "default"};
    collectUnknown(rl, known, def, "relations.");
}

/// 合并后的整体语义校验（引用完整性；CTR-PL-01）
void semanticCheck(Collector& c, const Definition& def) {
    for (std::size_t i = 0; i < def.views.size(); ++i) {
        const ViewRule& v = def.views[i];
        for (std::size_t j = 0; j < v.filters.size(); ++j) {
            const PhaseFilterRule& f = v.filters[j];
            const std::string fp = entryPath("views", i, "phaseFilters") + "[" +
                                   std::to_string(j) + "]";
            for (const auto& t : f.includeTypes) {
                if (!def.findType(t)) c.add(fp, "includeTypes", "unknown entity type: " + t);
            }
            for (const auto& t : f.excludeTypes) {
                if (!def.findType(t)) c.add(fp, "excludeTypes", "unknown entity type: " + t);
            }
            for (const auto& g : f.requireFlags) {
                if (!def.findFlag(g)) c.add(fp, "requireFlags", "unknown flag: " + g);
            }
            for (const auto& g : f.excludeFlags) {
                if (!def.findFlag(g)) c.add(fp, "excludeFlags", "unknown flag: " + g);
            }
        }
    }
    for (std::size_t i = 0; i < def.actions.size(); ++i) {
        const ActionDef& a = def.actions[i];
        const std::string p = entryPath("actions", i, "");
        for (const auto& g : a.setsFlags) {
            if (!def.findFlag(g)) c.add(p, "setsFlags", "unknown flag: " + g);
        }
        for (const auto& g : a.clearsFlags) {
            if (!def.findFlag(g)) c.add(p, "clearsFlags", "unknown flag: " + g);
        }
        if (!a.setsDynamicState.empty() && !def.hasState(a.setsDynamicState)) {
            c.add(p, "setsDynamicState", "unknown dynamic state: " + a.setsDynamicState);
        }
        for (std::size_t j = 0; j < a.requires.size(); ++j) {
            const std::string& g = a.requires[j];
            if (!isBuiltinGate(g)) continue;
            const auto parts = splitGate(g);
            const std::string gp = p + ".requires[" + std::to_string(j) + "]";
            if (parts.first == "$flag") {
                if (!def.findFlag(parts.second)) c.add(gp, "requires", "unknown flag: " + parts.second);
            } else if (parts.first == "$state") {
                if (!def.hasState(parts.second)) {
                    c.add(gp, "requires", "unknown dynamic state: " + parts.second);
                }
            } else if (parts.first == "$action" || parts.first == "$not-action") {
                bool found = false;
                for (const auto& other : def.actions) {
                    if (other.key == parts.second) found = true;
                }
                if (!found) c.add(gp, "requires", "unknown action: " + parts.second);
            } else if (parts.first == "$in-sequence" || parts.first == "$reversible" ||
                       parts.first == "$confidence-min") {
                // 无需引用校验
            } else {
                c.add(gp, "requires", "unknown builtin gate: " + parts.first);
            }
        }
    }
    for (const auto& f : def.flags) {
        for (const auto& x : f.exclusive) {
            if (!def.findFlag(x)) c.add("flags", "exclusive", "unknown flag: " + x);
        }
    }
    if (!def.relations.kinds.empty()) {
        for (const auto& k : def.relations.kinds) {
            if (k.key.empty()) c.add("relations.kinds", "key", "empty kind key");
        }
    }
    if (!def.relations.defaultState.empty()) {
        bool found = false;
        for (const auto& s : def.relations.states) {
            if (s.key == def.relations.defaultState) found = true;
        }
        if (!found) c.add("relations", "default", "unknown relation state: " + def.relations.defaultState);
    }
    for (std::size_t i = 0; i < def.window.patterns.size(); ++i) {
        const auto& p = def.window.patterns[i];
        for (const auto& t : p.appliesToTypes) {
            if (t == "*") continue;
            if (!def.findType(t)) {
                c.add(entryPath("strikeWindow.patterns", i, "appliesToTypes"),
                      "appliesToTypes", "unknown entity type: " + t);
            }
        }
    }
    if (!def.factors.empty()) {
        if (def.totalWeightPpm <= 0) {
            c.add("items", "weight", "sum of factor weights must be > 0");
        }
        if (def.bands.empty()) {
            c.add("bands", "bands", "bands are required when factors are declared");
        }
    }
}

}  // namespace

ValidateOutcome buildDefinition(const Definition& base, const json& pkg) {
    ValidateOutcome out;
    Collector c;
    Definition def = base;

    if (!pkg.is_object()) {
        out.code = 1000;
        out.message = "policy package must be a JSON object";
        c.add("", "", out.message);
        out.issues = c.issues;
        return out;
    }

    const std::string ns = optStr(pkg, "policiesNamespace");
    const std::string sv = optStr(pkg, "schemaVersion");
    const std::string kind = optStr(pkg, "kind");

    if (ns.empty()) c.add("", "policiesNamespace", "missing required field (non-empty string)");
    if (sv.empty()) {
        c.add("", "schemaVersion", "missing required field (non-empty string)");
    }
    int major = 0;
    if (!sv.empty() && !parseSchemaVersion(sv, major)) {
        c.add("", "schemaVersion", "must be MAJOR.MINOR.PATCH");
    }
    if (kind.empty()) {
        c.add("", "kind", "missing required field");
    } else if (kind != kKindEntityTypes && kind != kKindThreatFactors) {
        c.add("", "kind", "unsupported kind: " + kind);
    }

    auto iit = pkg.find("items");
    if (iit == pkg.end() || !iit->is_array()) {
        c.add("items", "items", "missing required field (array)");
    } else if (iit->empty()) {
        c.add("items", "items", "must not be empty");
    }

    // MAJOR 不匹配 → 1006（MUST NOT 静默降级，§5.2）
    bool versionMismatch = false;
    if (!sv.empty() && parseSchemaVersion(sv, major) && major != kSupportedPoliciesMajor) {
        versionMismatch = true;
        c.add("", "schemaVersion",
              "unsupported MAJOR (engine supports " + std::to_string(kSupportedPoliciesMajor) + ")");
    }

    if (def.loaded) {
        if (!ns.empty() && def.ns != ns) {
            c.add("", "policiesNamespace", "namespace mismatch with loaded policies: " + def.ns);
        }
    }

    // 结构问题已足以拒绝 → 直接返回（不做合并，保证原子性）
    bool structural = false;
    for (const auto& is : c.issues) {
        if (is.path == "items" || is.path.empty() || is.path == "bands") structural = true;
    }
    if (structural) {
        out.code = versionMismatch ? 1006 : 1000;
        out.message = versionMismatch ? "unsupported policies MAJOR" : "invalid policy package";
        out.issues = c.issues;
        return out;
    }

    // ---- 合并 ----
    if (!def.loaded) {
        def.ns = ns;
        def.schemaVersion = sv;
        def.major = major;
        // 缺省编号规则（protocol.md §5.5 示例的同形缺省；CTR-PL-04 缺省须文档化）
        def.numbering = NumberingRule{};
        def.confidence.defaultSource.clear();
    }

    const std::set<std::string> knownTop = {"policiesNamespace", "schemaVersion", "kind", "items",
                                            "numbering",   "geometry",      "reference",
                                            "dynamicStates", "dedup",      "confidence",
                                            "flags",       "views",         "actions",
                                            "relations",   "bands",         "strikeWindow",
                                            "rank",        "trajectory"};
    collectUnknown(pkg, knownTop, def, "");

    if (kind == kKindEntityTypes) {
        // 同 kind 的 `items` **整体替换**（后装载者为准）——保证可"换一套类型集"而不残留旧条目
        def.types.clear();
        def.typeOrder.clear();
        parseEntityTypes(*iit, c, def);
    } else {
        def.factors.clear();
        def.totalWeightPpm = 0;
        parseFactors(*iit, c, def);
    }

    auto seg = [&](const char* name) -> const json* {
        auto it = pkg.find(name);
        if (it == pkg.end() || it->is_null()) return nullptr;
        return &(*it);
    };
    if (const json* v = seg("numbering")) parseNumbering(*v, c, def);
    if (const json* v = seg("geometry")) parseGeometry(*v, c, def);
    if (const json* v = seg("reference")) parseReference(*v, c, def);
    if (const json* v = seg("dynamicStates")) parseDynamicStates(*v, c, def);
    if (const json* v = seg("dedup")) parseDedup(*v, c, def);
    if (const json* v = seg("confidence")) parseConfidence(*v, c, def);
    if (const json* v = seg("flags")) parseFlags(*v, c, def);
    if (const json* v = seg("views")) parseViews(*v, c, def);
    if (const json* v = seg("actions")) parseActions(*v, c, def);
    if (const json* v = seg("relations")) parseRelations(*v, c, def);
    if (const json* v = seg("bands")) parseBands(*v, c, def);
    if (const json* v = seg("strikeWindow")) parseWindow(*v, c, def);
    if (const json* v = seg("rank")) parseRank(*v, c, def);
    if (const json* v = seg("trajectory")) parseTrack(*v, c, def);

    semanticCheck(c, def);

    if (!c.issues.empty()) {
        out.code = versionMismatch ? 1006 : 1000;
        out.message = versionMismatch ? "unsupported policies MAJOR" : "policy package rejected";
        out.issues = c.issues;
        return out;
    }

    json eff = definitionToJson(def);
    def.digest = fnv1a64Hex(canonicalBytes(eff));
    def.version = def.ns + ":" + def.schemaVersion + ":" + def.digest;
    def.loaded = true;

    out.code = 0;
    out.message = "ok";
    out.def = def;
    return out;
}

}  // namespace detail
}  // namespace entity_ledger
