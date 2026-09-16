# scripts/acceptance.ps1 · entity-ledger 独立验收脚本（退出码 0/1）
#
# 权威依据：docs/需求/entity-ledger需求专篇.md（41 条需求）
#   ① §7 验收清单 17 行 —— 逐行变成一条可执行检查（S07-01..S07-17）
#   ② §3 功能需求 41 条（ELG-REG 6 / ELG-ID 5 / ELG-RATE 6 / ELG-RANK 4 /
#                        ELG-TRK 6 / ELG-ACT 6 / ELG-INTEL 3 / ELG-NFR 5）
#   ③ §1.4 硬约束 + §4「引擎 vs 规则」判据
#   ④ 上游冻结契约 phase-engine/docs/契约/protocol.md
#      （P1–P10、§2 实体标识 CTR-EN-01..08、§3 错误码、§4 事件名、§5 规则包 schema、§6 反向接口）
#
# 设计：**引擎行为一律由 tests/selftest 断言**（selftest --json 输出逐用例结果与需求编号），
# 本脚本只做它做不了的三件事：构建生命周期、结构纪律检索（业务词/硬编码/文案/跨仓）、
# 需求↔用例对账。这样"行为口径"只有一个来源，不会出现脚本与单测两套断言的漂移。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts/acceptance.ps1
#   ... -SkipBuild                只跑自测与检查（复用已有构建产物）
#   ... -Config Debug             换构建配置
#   ... -Generator "Ninja"        换生成器（单配置生成器也可）
#
# 兼容 Windows PowerShell 5.1（不依赖 pwsh / PS7 语法）。
param(
    [string]$BuildDir = "build",
    [string]$Config = "Release",
    [string]$Generator = "Visual Studio 17 2022",
    [string]$Arch = "x64",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$script:Results = New-Object System.Collections.Generic.List[object]
$script:ChecksFailed = 0

# ------------------------------------------------------------------ 输出小工具
function Check([string]$id, [string]$title, [bool]$ok, [string]$detail) {
    $state = "PASS"
    if (-not $ok) { $state = "FAIL"; $script:ChecksFailed++ }
    $script:Results.Add([pscustomobject]@{ Id = $id; Title = $title; Ok = $ok; Detail = $detail })
    $color = "Green"
    if (-not $ok) { $color = "Red" }
    Write-Host ("  [{0}] {1} · {2}" -f $state, $id, $title) -ForegroundColor $color
    if ($detail) { Write-Host ("         {0}" -f $detail) -ForegroundColor DarkGray }
}

function Section([string]$title) {
    Write-Host ""
    Write-Host ("=" * 78)
    Write-Host $title
    Write-Host ("=" * 78)
}

function Rel([string]$full) {
    $root = $script:Repo
    if ($full.StartsWith($root)) { return $full.Substring($root.Length).TrimStart('\', '/') }
    return $full
}

function Format-Hits($hits) {
    if (-not $hits -or $hits.Count -eq 0) { return "" }
    $head = @($hits | Select-Object -First 5)
    $s = "：" + ($head -join "；")
    if ($hits.Count -gt 5) { $s += ("；…共 {0} 处" -f $hits.Count) }
    return $s
}

# 结构检索：返回命中列表（"文件:行号"）
function SearchHits([string[]]$files, [string]$regex, [string[]]$skipLineRegex) {
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $n = 0
        foreach ($line in [System.IO.File]::ReadAllLines($f)) {
            $n++
            if ($line -notmatch $regex) { continue }
            if ($skipLineRegex) {
                $skip = $false
                foreach ($s in $skipLineRegex) { if ($line -match $s) { $skip = $true; break } }
                if ($skip) { continue }
            }
            $hits.Add(("{0}:{1}" -f (Rel $f), $n))
        }
    }
    return $hits
}

# 去掉 C/C++ 注释后的文本（注释里的说明文字不是"引擎产物"，也不该触发文案守卫）
function Strip-Comments([string]$text) {
    $noBlock = [regex]::Replace($text, '/\*.*?\*/', '', 'Singleline')
    return [regex]::Replace($noBlock, '//[^\r\n]*', '')
}

# 结构检索（先去注释）：命中列表
function SearchCode([string[]]$files, [string]$regex) {
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $stripped = Strip-Comments ([System.IO.File]::ReadAllText($f))
        $n = 0
        foreach ($line in ($stripped -split "`r?`n")) {
            $n++
            if ($line -match $regex) { $hits.Add(("{0}:{1}" -f (Rel $f), $n)) }
        }
    }
    return $hits
}

function CollectFiles([string[]]$dirs, [string[]]$exts, [string[]]$excludeDirs) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($d in $dirs) {
        $full = Join-Path $script:Repo $d
        if (-not (Test-Path $full)) { continue }
        Get-ChildItem -Path $full -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($exts -notcontains $_.Extension) { return }
            $rel = Rel $_.FullName
            foreach ($x in $excludeDirs) { if ($rel -like ($x + "*")) { return } }
            $out.Add($_.FullName)
        }
    }
    return $out
}

# ------------------------------------------------------------------ 前置
$script:Repo = Split-Path -Parent $PSScriptRoot
Push-Location $script:Repo
try {
    Write-Host "entity-ledger 独立验收（需求专篇 §7 逐条 + 需求↔用例对账 + 结构纪律）"
    Write-Host ("仓库：{0}" -f $script:Repo)
    Write-Host ("PowerShell：{0}" -f $PSVersionTable.PSVersion)

    $cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
    if (-not $cmake) {
        foreach ($p in @("C:\Program Files\CMake\bin\cmake.exe",
                         "C:\Program Files (x86)\CMake\bin\cmake.exe")) {
            if (Test-Path $p) { $cmake = $p; break }
        }
    }
    if (-not $cmake) { Write-Host "找不到 cmake（>= 3.20）" -ForegroundColor Red; exit 1 }
    $cmakeVersion = (& $cmake --version | Select-Object -First 1)
    Write-Host ("cmake：{0}（{1}）" -f $cmake, $cmakeVersion)

    $buildPath = Join-Path $script:Repo $BuildDir
    $isMultiConfig = ($Generator -like "Visual Studio*")
    $binCandidates = @()
    if ($isMultiConfig) { $binCandidates += (Join-Path $buildPath "bin\$Config") }
    $binCandidates += (Join-Path $buildPath "bin\$Config")
    $binCandidates += (Join-Path $buildPath "bin")

    function Resolve-Bin() {
        foreach ($c in $binCandidates) {
            if ((Test-Path (Join-Path $c "selftest.exe")) -or (Test-Path (Join-Path $c "selftest"))) {
                return $c
            }
        }
        return $binCandidates[0]
    }

    # ================================================================ ① 构建（ELG-NFR-04）
    Section "① 构建生命周期（ELG-NFR-04：一条命令构建 → 一条命令验收）"

    $configureOk = $false
    $buildOk = $false
    if ($SkipBuild) {
        $configureOk = (Test-Path (Join-Path $buildPath "CMakeCache.txt"))
        $buildOk = (Test-Path (Join-Path (Resolve-Bin) "selftest.exe")) -or
                   (Test-Path (Join-Path (Resolve-Bin) "selftest"))
        Check "C01" "构建：-SkipBuild 复用已有产物" ($configureOk -and $buildOk) `
            ("configure={0} binary={1}" -f $configureOk, $buildOk)
    } else {
        Write-Host ("    cmake -S . -B {0} -G '{1}'" -f $BuildDir, $Generator)
        & $cmake -S $script:Repo -B $buildPath -G $Generator -A $Arch 2>&1 |
            ForEach-Object { Write-Host ("      {0}" -f $_) }
        $configureOk = ($LASTEXITCODE -eq 0)

        Write-Host ("    cmake --build {0} --config {1}" -f $BuildDir, $Config)
        & $cmake --build $buildPath --config $Config 2>&1 |
            ForEach-Object { Write-Host ("      {0}" -f $_) }
        $buildOk = ($LASTEXITCODE -eq 0)

        $bin = Resolve-Bin
        $hasSelftest = (Test-Path (Join-Path $bin "selftest.exe")) -or
                       (Test-Path (Join-Path $bin "selftest"))
        $hasExamples = ((Test-Path (Join-Path $bin "example_minimal.exe")) -or
                        (Test-Path (Join-Path $bin "example_minimal"))) -and
                       ((Test-Path (Join-Path $bin "example_consistency.exe")) -or
                        (Test-Path (Join-Path $bin "example_consistency")))
        $hasLib = (Test-Path (Join-Path $buildPath "lib\$Config\entity_ledger.lib")) -or
                  (Test-Path (Join-Path $buildPath "lib\libentity_ledger.a")) -or
                  (Test-Path (Join-Path $buildPath "lib\entity_ledger.lib")) -or
                  (Test-Path (Join-Path $buildPath "lib\libentity_ledger.a"))
        Check "C01" "构建：配置 + 编译通过，产物齐全（entity_ledger + selftest + 2 个示例）" `
            ($configureOk -and $buildOk -and $hasSelftest -and $hasExamples -and $hasLib) `
            ("configure={0} build={1} lib={2} selftest={3} examples={4} bin={5}" -f `
                $configureOk, $buildOk, $hasLib, $hasSelftest, $hasExamples, (Rel $bin))
    }

    $bin = Resolve-Bin
    $selftestExe = Join-Path $bin "selftest.exe"
    if (-not (Test-Path $selftestExe)) { $selftestExe = Join-Path $bin "selftest" }

    # ① -3 CMake 最低版本 >= 3.20（需求 §1.4 技术约定）
    $cmakeLists = Get-Content -Raw -Encoding UTF8 (Join-Path $script:Repo "CMakeLists.txt")
    $minOk = $false
    if ($cmakeLists -match 'cmake_minimum_required\s*\(\s*VERSION\s+([0-9]+\.[0-9]+)') {
        $minOk = ([version]$Matches[1] -ge [version]"3.20")
    }
    $cxx17 = ($cmakeLists -match 'CMAKE_CXX_STANDARD\s+17')
    Check "C02" "构建：CMake >= 3.20 且 C++17（需求 §1.4）" ($minOk -and $cxx17) `
        ("cmake_min={0} cxx17={1}" -f $minOk, $cxx17)

    # ================================================================ ② selftest（行为口径唯一来源）
    Section "② 零依赖自测（tests/selftest + --json 对账）"

    # ② -1 人读输出：断言规范要求的汇总行格式
    $humanPath = Join-Path ([System.IO.Path]::GetTempPath()) ("entity-ledger-self-{0}.txt" -f $PID)
    $summaryLine = ""
    if (Test-Path $selftestExe) {
        & $selftestExe > $humanPath
        $humanRaw = [System.IO.File]::ReadAllText($humanPath, [System.Text.Encoding]::UTF8)
        $m = [regex]::Match($humanRaw, '用例\s+(\d+)\s+个（失败\s+(\d+)\s*）｜断言\s+(\d+)\s+条（失败\s+(\d+)\s*）')
        if ($m.Success) { $summaryLine = $m.Value }
    }
    Check "C03" "自测输出含规定汇总行「用例 N 个（失败 M）｜断言 X 条（失败 Y）」" `
        ($summaryLine -ne "") ("汇总行：{0}" -f $(if ($summaryLine) { $summaryLine } else { "未找到" }))

    # ② -2 机检输出：逐用例结果与需求编号
    $jsonOk = $false
    $data = $null
    $jsonPath = Join-Path ([System.IO.Path]::GetTempPath()) ("entity-ledger-selftest-{0}.json" -f $PID)
    if (Test-Path $selftestExe) {
        # 子进程直接写文件：--json 输出 UTF-8（含中文失败信息），走管道会被控制台代码页解成乱码
        & $selftestExe --json > $jsonPath
        $raw = ""
        if (Test-Path $jsonPath) { $raw = [System.IO.File]::ReadAllText($jsonPath, [System.Text.Encoding]::UTF8) }
        # 容错：只取 JSON 主体（stdout 上若有旁白行也不影响机检解析）
        $first = $raw.IndexOf('{')
        $last = $raw.LastIndexOf('}')
        if ($first -ge 0 -and $last -gt $first) { $raw = $raw.Substring($first, $last - $first + 1) }
        try {
            $data = $raw | ConvertFrom-Json
            $jsonOk = $true
        } catch {
            Write-Host "    selftest --json 解析失败：$($_.Exception.Message)" -ForegroundColor Red
            if ($raw.Length -gt 0) { Write-Host ($raw.Substring(0, [Math]::Min(400, $raw.Length))) }
        }
    }
    Check "C04" "自测可执行且 --json 输出可解析" $jsonOk ("exe={0}" -f (Rel $selftestExe))

    if (-not $jsonOk) {
        Section "汇总"
        Write-Host "无法读取自测结果，后续按用例对账的检查全部失败。" -ForegroundColor Red
        Check "C04b" "自测结果可用" $false "selftest --json 无有效输出"
    } else {
        Write-Host ("    用例 {0} 个（失败 {1}）｜断言 {2} 条（失败 {3}）｜耗时 {4:N1} ms｜结果 {5}" -f `
            $data.cases, $data.casesFailed, $data.asserts, $data.assertsFailed, $data.elapsedMs, $data.result)
        Check "C05" "自测全绿：用例失败 0 且断言失败 0" `
            (($data.casesFailed -eq 0) -and ($data.assertsFailed -eq 0)) `
            ("cases={0}/{1} asserts={2}/{3}" -f $data.cases, $data.casesFailed, $data.asserts, $data.assertsFailed)

        # 用例索引：名字 → { ok, reqs }
        $caseByName = @{}
        $reqToCases = @{}
        foreach ($c in $data.details) {
            $caseByName[$c.name] = $c
            foreach ($r in $c.reqs) {
                if (-not $reqToCases.ContainsKey($r)) {
                    $reqToCases[$r] = New-Object System.Collections.Generic.List[string]
                }
                $reqToCases[$r].Add($c.name)
            }
        }

        # ---- 需求专篇 ⟷ 用例对账（需求编号从专篇正文提取，避免脚本自带一份"抄写版"）
        $reqDocPath = Join-Path $script:Repo "docs\需求\entity-ledger需求专篇.md"
        $reqDoc = Get-Content -Raw -Encoding UTF8 $reqDocPath
        $allReqs = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($reqDoc, 'ELG-[A-Z]+-\d{2}')) {
            if (-not $allReqs.Contains($m.Value)) { $allReqs.Add($m.Value) }
        }
        $allReqs = @($allReqs | Sort-Object)
        Check "C06" "需求专篇提取到 41 条 ELG-* 需求条目" ($allReqs.Count -eq 41) `
            ("提取到 {0} 条（首/末：{1} / {2}）" -f $allReqs.Count, $allReqs[0], $allReqs[-1])

        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($r in $allReqs) {
            if (-not $reqToCases.ContainsKey($r)) { $missing.Add($r) }
        }
        Check "C07" "需求覆盖：41 条 ELG-* 每条都有用例引用" ($missing.Count -eq 0) `
            ("无对应用例：{0}" -f (($missing -join ", ") -replace '^$', '无'))

        $reqFailed = New-Object System.Collections.Generic.List[string]
        foreach ($r in $allReqs) {
            if (-not $reqToCases.ContainsKey($r)) { continue }
            $anyOk = $false
            foreach ($cn in $reqToCases[$r]) { if ($caseByName[$cn].ok) { $anyOk = $true } }
            if (-not $anyOk) { $reqFailed.Add($r) }
        }
        Check "C08" "需求覆盖：每条至少有一个通过用例" ($reqFailed.Count -eq 0) `
            ("未通过：{0}" -f (($reqFailed -join ", ") -replace '^$', '无'))
    }

    # ================================================================ ③ §7 验收清单逐条
    Section "③ 需求专篇 §7 验收清单（逐条，17 行）"

    $checklist = @(
        @{ Id = "S07-01"; Line = "空环境 clone → 一条命令构建 → 一条命令跑通验收（退出码 0）"
           Cases = @(); NeedsBuild = $true },
        @{ Id = "S07-02"; Line = "全仓检索实体类型名、高价值、硬编码窗口、内联动作文案 → 零命中"
           Cases = @(); Guard = "business-words" },
        @{ Id = "S07-03"; Line = "重复 targetNo 登记被拒绝"
           Cases = @("reg03_mission_scope_and_duplicate_no_rejected") },
        @{ Id = "S07-04"; Line = "同一目标三条来源观测合并为一条，来源标为多源；默认保守不误合"
           Cases = @("reg04_multisource_dedup_conservative") },
        @{ Id = "S07-05"; Line = "制造「某视图多两个目标」→ 一致性报告定位到具体编号与视图"
           Cases = @("id02a_consistency_localizes_count_mismatch") },
        @{ Id = "S07-06"; Line = "同一阶段两次查询可见集合一致"
           Cases = @("id03_visible_set_is_engine_owned_and_stable") },
        @{ Id = "S07-07"; Line = "制造类型漂移 → 被检出；走重判动作 → 允许并留痕"
           Cases = @("id04_type_binding_and_reclassify_trace") },
        @{ Id = "S07-08"; Line = "任取一目标导出逐因子得分，手算等于总分；调阈值后分档变化可复现"
           Cases = @("rate02_score_recomputable_by_hand", "rate03_bands_from_thresholds_not_boolean", "rate04_distance_uses_real_geometry") },
        @{ Id = "S07-09"; Line = "打击窗口为结构化时间区间，可复算"
           Cases = @("rate06_strike_window_is_computed_interval") },
        @{ Id = "S07-10"; Line = "连点两次 upgrade：第二次得到「已执行」语义（幂等），互斥冲突另给 1002"
           Cases = @("act02_idempotent_repeat_and_conflict_are_distinct") },
        @{ Id = "S07-11"; Line = "动作只产结构化事件，不产自然语言"
           Cases = @("act03_action_output_is_structured_only") },
        @{ Id = "S07-12"; Line = "未满足前置条件的动作被拒绝并给原因"
           Cases = @("act04_preconditions_all_reported") },
        @{ Id = "S07-13"; Line = "关系链成环被检出"
           Cases = @("intel01a_relation_crud_and_cycle_rejected", "intel01b_cyclic_kind_detected_and_queries_terminate") },
        @{ Id = "S07-14"; Line = "轨迹乱序写入后查询有序；超限返回截断标记；抽稀带标注"
           Cases = @("trk01_out_of_order_writes_ordered_queries", "trk02_range_query_truncation_flagged", "trk03_decimation_is_annotated") },
        @{ Id = "S07-15"; Line = "轨迹时间轴输出可被 map-2d 回放接口消费（由宿主适配）"
           Cases = @("trk04_timeline_matches_replay_shape") },
        @{ Id = "S07-16"; Line = "预测点带显式标记，不与实测点混淆"
           Cases = @("trk05_prediction_flagged_not_mixed") },
        @{ Id = "S07-17"; Line = "1000 实体评级全量 ≤ 10 ms；1 万点区间查询 ≤ 5 ms"
           Cases = @("nfr05_performance_thresholds") }
    )

    if (-not $jsonOk) {
        foreach ($item in $checklist) {
            Check $item.Id $item.Line $false "自测结果不可用，无法对账"
        }
    } else {
        foreach ($item in $checklist) {
            if ($item.ContainsKey("NeedsBuild")) {
                Check $item.Id $item.Line ($configureOk -and $buildOk) `
                    "配置与构建成功 = 空环境一条命令可构建（详见 ① 的输出）"
                continue
            }
            if ($item.ContainsKey("Guard")) { continue }  # 结构类条目在 ④ 统一给结论
            $missingCases = New-Object System.Collections.Generic.List[string]
            $failedCases = New-Object System.Collections.Generic.List[string]
            foreach ($cn in $item.Cases) {
                if (-not $caseByName.ContainsKey($cn)) { $missingCases.Add($cn); continue }
                if (-not $caseByName[$cn].ok) { $failedCases.Add($cn) }
            }
            $ok = ($missingCases.Count -eq 0) -and ($failedCases.Count -eq 0)
            $detail = "用例：{0}" -f ($item.Cases -join ", ")
            if ($missingCases.Count -gt 0) { $detail += "；缺失：" + ($missingCases -join ", ") }
            if ($failedCases.Count -gt 0) { $detail += "；失败：" + ($failedCases -join ", ") }
            Check $item.Id $item.Line $ok $detail
        }
    }

    # ================================================================ ④ 结构纪律
    Section "④ 结构纪律：业务词 / 硬编码窗口 / 内联文案 / 跨仓 import / 动作名 / 规则包 schema"

    # 检索范围（需求 §4 判据 + protocol.md P6/P7 的操作化）：
    #   纳入（引擎产物）：include/ src/ examples/ + 各 CMakeLists.txt
    #   豁免：policies/（规则包 —— 业务取值的**合法住所**）、docs/（需求与契约的引用语境）、
    #         tests/（自测把规则取值当数据驱动；且规范要求其汇总行为中文），scripts/（本脚本自带检索词）
    $engineFiles = [string[]]@(CollectFiles @("include", "src", "examples") `
        @(".h", ".hpp", ".cc", ".cpp") @())
    foreach ($f in @("CMakeLists.txt", "examples\CMakeLists.txt", "tests\CMakeLists.txt")) {
        $full = Join-Path $script:Repo $f
        if (Test-Path $full) { $engineFiles += $full }
    }
    Write-Host ("    检索范围 {0} 个引擎产物文件（policies/ docs/ tests/ scripts/ 豁免）" -f $engineFiles.Count)

    # C09：业务词零命中。模式拆开拼接 —— 本脚本内不出现业务词字面量（避免自指）
    $bizPattern = '机动' + '指挥节点|防空' + '火力阵地|防空' + '火力单元|通信' + '保障节点|通信' +
                  '枢纽节点|后勤' + '运输车队|高' + '价值|红' + '方|持续' + '跟踪|重点' + '监视'
    $bizHits = @(SearchCode $engineFiles $bizPattern)
    Check "C09" "§4 判据 / P6：引擎产物内业务词（实体类型名 / 高价值 / 动作语义文案）零命中" `
        ($bizHits.Count -eq 0) ("命中 {0} 处{1}" -f $bizHits.Count, (Format-Hits $bizHits))

    # C09b：业务取值确实住在规则包里（否则 C09 的"零命中"可能是假绿）
    $policyFiles = [string[]]@(CollectFiles @("policies") @(".json") @())
    $policyBizHits = @(SearchHits $policyFiles $bizPattern @())
    Check "C09b" "§4 / P7：业务取值只住在规则包 policies/mapapp/" ($policyBizHits.Count -gt 0) `
        ("规则包内命中 {0} 处（说明类型名等来自外部数据而非引擎）" -f $policyBizHits.Count)

    # C10：硬编码打击窗口字符串零命中（ELG-RATE-06 的现状缺陷）
    $windowPattern = '12' + '\s*分\s*' + '32\s*秒'
    $repoFiles = [string[]]@(CollectFiles @("include", "src", "examples", "tests", "scripts", "policies") `
        @(".h", ".hpp", ".cc", ".cpp", ".ps1", ".json", ".txt", ".md") @())
    $repoFiles += (Join-Path $script:Repo "CMakeLists.txt")
    $windowHits = @(SearchCode $repoFiles $windowPattern)
    Check "C10" "ELG-RATE-06：全仓（除 docs/）检索硬编码窗口字符串零命中" ($windowHits.Count -eq 0) `
        ("命中 {0} 处{1}" -f $windowHits.Count, (Format-Hits $windowHits))

    # C10b：演示口径以**规则参数**形式存在（752000 ms），而不是引擎常量
    $windowParamFiles = [string[]]@(CollectFiles @("policies") @(".json") @())
    $windowParamHits = @(SearchHits $windowParamFiles '752000' @())
    $engineWindow = @(SearchCode ([string[]]@(CollectFiles @("include", "src") @(".h", ".hpp", ".cc", ".cpp") @())) '752000')
    Check "C10b" "ELG-RATE-06：窗口提前量是规则参数（引擎内零常量）" `
        (($windowParamHits.Count -ge 1) -and ($engineWindow.Count -eq 0)) `
        ("规则包 {0} 处；引擎内 {1} 处" -f $windowParamHits.Count, $engineWindow.Count)

    # C11：内联自然语言文案零命中（引擎产物里字符串字面量 MUST NOT 出现 CJK）
    #      注释豁免（先剥注释）；测试豁免（规范要求其中文汇总行）；examples 与引擎同标准
    $cjkFiles = [string[]]@(CollectFiles @("include", "src", "examples") @(".h", ".hpp", ".cc", ".cpp") @())
    $cjkHits = @(SearchCode $cjkFiles '[\u4e00-\u9fff]')
    Check "C11" "ELG-ACT-03：引擎产物与示例的字符串里零 CJK 文案（注释豁免）" ($cjkHits.Count -eq 0) `
        ("命中 {0} 处{1}" -f $cjkHits.Count, (Format-Hits $cjkHits))

    # C12：跨仓 import 零命中，且依赖仅 nlohmann/json（P1 / P2 / P3 / ELG-NFR-01）
    $otherRepos = '(phase|map_2d|map-2d|entity_ledger_other|resource_alloc|resource-alloc|scoring|' +
                  'topology|view_composer|view-composer|alert_engine|alert-engine|report_engine|' +
                  'report-engine|selfcheck|geo_data|geo-data|media_player|media-player|telemetry_store|' +
                  'telemetry-store|device_ingest|device-ingest|realtime_hub|realtime-hub|drogon|Drogon|' +
                  'sqlite|mysql|pqxx|libpq|nanodbc|oatpp|crow|httplib)'
    $incHits = @(SearchCode $engineFiles ('#\s*include\s*[<"]' + $otherRepos))
    Check "C12" "P1/P2/P3 / ELG-NFR-01：跨仓 import 与 Web/SQL 依赖零命中" ($incHits.Count -eq 0) `
        ("命中 {0} 处{1}" -f $incHits.Count, (Format-Hits $incHits))

    $allIncludes = New-Object System.Collections.Generic.List[string]
    foreach ($f in $engineFiles) {
        foreach ($line in [System.IO.File]::ReadAllLines($f)) {
            $m = [regex]::Match($line, '^\s*#\s*include\s+(?:<([^>]+)>|"([^"]+)")')
            if ($m.Success) {
                if ($m.Groups[1].Success) { $allIncludes.Add($m.Groups[1].Value) }
                else { $allIncludes.Add($m.Groups[2].Value) }
            }
        }
    }
    # 只允许：C/C++ 标准库（无扩展名的小写头）、本模块公开头（entity_ledger/...）、
    # 内部头（internal.h）、nlohmann/json。其余一律视为外部依赖。
    $nonJson = $allIncludes | Where-Object {
        ($_ -notmatch '^(entity_ledger/|internal\.h$)') -and
        ($_ -notmatch '^[a-z_]+$') -and
        ($_ -notmatch '^(nlohmann|third_party)')
    }
    Check "C13" "依赖仅 nlohmann/json + 标准库（无其它外部头）" ($nonJson.Count -eq 0) `
        ("非标准库/非 nlohmann 的 include：{0}" -f (($nonJson -join ", ") -replace '^$', '无'))

    # C14：动作集由规则声明 —— 动作名在引擎产物内零命中，且在规则包内存在（ELG-ACT-01）
    # 判据：**引号字面量**形式的动作名（内建动作名 MUST NOT 出现），
    # 加上裸词 watch / upgrade（不可能是机制词）；track 作为"轨迹"机制词合法，故只查引号形式。
    $actionPattern = '"(watch|strike|track|upgrade)"' + '|\b' + 'watch' + '\b|\b' + 'upgrade' + '\b'
    $actionHits = @(SearchCode ([string[]]@(CollectFiles @("include", "src") @(".h", ".hpp", ".cc", ".cpp") @())) $actionPattern)
    $actionPolicyHits = @(SearchHits ([string[]]@(CollectFiles @("policies") @(".json") @())) '"(watch|strike|track|upgrade)"')
    Check "C14" "ELG-ACT-01：动作名在引擎源码内零命中，且只住在规则包" `
        (($actionHits.Count -eq 0) -and ($actionPolicyHits.Count -ge 4)) `
        ("引擎 {0} 处；规则包 {1} 处" -f $actionHits.Count, $actionPolicyHits.Count)

    # C15：威胁分档取值（high/mid/low）不得在引擎源码内做字面量判断（ELG-RATE-01/03）
    $bandPattern = '"(high|mid|low)"'
    $bandHits = @(SearchCode ([string[]]@(CollectFiles @("include", "src") @(".h", ".hpp", ".cc", ".cpp") @())) $bandPattern)
    Check "C15" "ELG-RATE-01/03：引擎源码内无分档字面量（分档由规则阈值决定）" ($bandHits.Count -eq 0) `
        ("命中 {0} 处{1}" -f $bandHits.Count, (Format-Hits $bandHits))

    # C16：规则包 schema（protocol.md §5.1 骨架四字段 + §5.3 kind + §5.2 MAJOR）
    $policyOk = $true
    $policyDetail = New-Object System.Collections.Generic.List[string]
    foreach ($f in $policyFiles) {
        $pkg = $null
        try { $pkg = Get-Content -Raw -Encoding UTF8 $f | ConvertFrom-Json } catch { }
        $name = Rel $f
        if (-not $pkg) { $policyOk = $false; $policyDetail.Add("$name 非法 JSON"); continue }
        $props = @($pkg.PSObject.Properties.Name)
        foreach ($k in @("policiesNamespace", "schemaVersion", "kind", "items")) {
            if ($props -notcontains $k) { $policyOk = $false; $policyDetail.Add("$name 缺 $k") }
        }
        if ($props -contains "kind") {
            if (@("entityTypes", "threatFactors") -notcontains $pkg.kind) {
                $policyOk = $false; $policyDetail.Add("$name kind=$($pkg.kind) 非本引擎 kind")
            }
        }
        if ($props -contains "schemaVersion") {
            if ($pkg.schemaVersion -notmatch '^\d+\.\d+\.\d+$') {
                $policyOk = $false; $policyDetail.Add("$name schemaVersion 非语义化版本")
            } elseif ([int]($pkg.schemaVersion.Split('.')[0]) -ne 1) {
                $policyOk = $false; $policyDetail.Add("$name MAJOR != 引擎支持值 1")
            }
        }
        if ($props -contains "items" -and @($pkg.items).Count -eq 0) {
            $policyOk = $false; $policyDetail.Add("$name items 为空")
        }
    }
    Check "C16" "protocol.md §5：规则包骨架四字段 + kind ∈ {entityTypes, threatFactors} + MAJOR=1" `
        $policyOk (($policyDetail -join "；") -replace '^$', ("检查 {0} 个规则文件，全部通过" -f $policyFiles.Count))

    # §7 第 2 行的结论（编号顺延为 C17 的位置，但按 §7 的行号报告为 S07-02）（业务词 / 硬编码窗口 / 内联文案 三项守卫的合取）
    $s07_02_ok = ($bizHits.Count -eq 0) -and ($policyBizHits.Count -gt 0) -and
                 ($windowHits.Count -eq 0) -and ($windowParamHits.Count -ge 1) -and
                 ($engineWindow.Count -eq 0) -and ($cjkHits.Count -eq 0)
    Check "S07-02" "全仓检索实体类型名 / 高价值 / 硬编码窗口 / 内联动作文案 → 零命中" $s07_02_ok `
        ("业务词 {0} 处｜窗口字符串 {1} 处｜引擎内窗口常量 {2} 处｜CJK 文案 {3} 处；规则包（合法住所）业务词 {4} 处" -f `
            $bizHits.Count, $windowHits.Count, $engineWindow.Count, $cjkHits.Count, $policyBizHits.Count)

    # ================================================================ ⑤ 反向接口与入口纪律
    Section "⑤ 反向接口纪律：IEntitySink / IEntityStore / IClock / ILogSink 全部由宿主注入（P8/P9）"

    $headerPath = Join-Path $script:Repo "include\entity_ledger\entity_ledger.h"
    $headerOk = Test-Path $headerPath
    $headerText = ""
    if ($headerOk) { $headerText = Get-Content -Raw -Encoding UTF8 $headerPath }

    $hasSink = ($headerText -match 'class\s+IEntitySink') -and
               ($headerText -match 'virtual\s+void\s+onEntityChanged') -and
               ($headerText -match 'virtual\s+void\s+onTargetState') -and
               ($headerText -match 'virtual\s+void\s+onConsistency')
    $hasStore = ($headerText -match 'class\s+IEntityStore') -and
                ($headerText -match 'virtual\s+bool\s+save') -and
                ($headerText -match 'virtual\s+bool\s+load')
    $hasClock = ($headerText -match 'class\s+IClock') -and ($headerText -match 'virtual\s+int64_t\s+nowMs')
    $hasLog = ($headerText -match 'class\s+ILogSink') -and ($headerText -match 'commandAudit')
    Check "C18" "公开头声明四个反向接口 IEntitySink / IEntityStore / IClock / ILogSink" `
        ($hasSink -and $hasStore -and $hasClock -and $hasLog) `
        ("sink={0} store={1} clock={2} log={3}" -f $hasSink, $hasStore, $hasClock, $hasLog)

    $injectedAll = ($headerText -match 'std::shared_ptr<IEntityStore>\s+store') -and
                   ($headerText -match 'std::shared_ptr<IClock>\s+clock') -and
                   ($headerText -match 'std::shared_ptr<IEntitySink>\s+sink') -and
                   ($headerText -match 'std::shared_ptr<ILogSink>\s+log')
    Check "C19" "四个出口全部经 EntityLedgerOptions 注入（无内建实现、无全局单例）" $injectedAll `
        "EntityLedgerOptions{store,clock,sink,log} 四个可空 shared_ptr"

    $srcFiles = [string[]]@(CollectFiles @("src") @(".cc", ".h") @())
    $dbHits = @(SearchCode $srcFiles '(SQLite|sqlite3|mysql_|PQexec|nanodbc|drogon::|Drogon|listen\(|EventHub|broadcast\()')
    Check "C20" "引擎内无落库 / 无广播 / 无 Web 框架调用（出口只走反向接口）" ($dbHits.Count -eq 0) `
        ("命中 {0} 处{1}" -f $dbHits.Count, (Format-Hits $dbHits))

    # C21：唯一公开头（其余头文件是内部实现细节）
    $publicHeaders = @()
    $includeDir = Join-Path $script:Repo "include"
    if (Test-Path $includeDir) {
        $publicHeaders = @(Get-ChildItem $includeDir -Recurse -File -Filter *.h | ForEach-Object { Rel $_.FullName })
    }
    Check "C21" "唯一公开头 include/entity_ledger/entity_ledger.h（P1）" `
        (($publicHeaders.Count -eq 1) -and ($publicHeaders[0] -eq "include\entity_ledger\entity_ledger.h")) `
        ("公开头：{0}" -f ($publicHeaders -join ", "))

    $internalH = Join-Path $script:Repo "src\internal.h"
    $internalGuarded = $false
    if (Test-Path $internalH) {
        $t = Get-Content -Raw -Encoding UTF8 $internalH
        $internalGuarded = ($t -match '宿主 MUST NOT 包含')
    }
    Check "C22" "内部头 src/internal.h 明确标注宿主不可包含" $internalGuarded `
        "src/internal.h 头部注明'MUST NOT 被包含'"

    # C23：PhaseContext 是**镜像**形状，不 import phase-engine（P1）
    $mirrorOk = ($headerText -match 'struct\s+PhaseContext') -and
                ($headerText -match 'phaseKey') -and ($headerText -match 'scenarioKey') -and
                ($headerText -match 'enteredAt') -and ($headerText -match 'missionId') -and
                ($headerText -match 'MUST NOT 互相 import')
    Check "C23" "protocol.md §1.4：PhaseContext 五字段镜像（引擎间不 import）" $mirrorOk `
        "公开头内 PhaseContext{phaseKey,seq,scenarioKey,enteredAt,missionId}"

    # C24：错误码与事件名（protocol.md §3.2 / §4）
    $codesOk = ($headerText -match 'BadRequest\s*=\s*1000') -and
               ($headerText -match 'Conflict\s*=\s*1002') -and
               ($headerText -match 'GateUnmet\s*=\s*1003') -and
               ($headerText -match 'NotFound\s*=\s*1004') -and
               ($headerText -match 'Internal\s*=\s*1005') -and
               ($headerText -match 'VersionMismatch\s*=\s*1006')
    $code1001 = @(SearchCode ([string[]]@(CollectFiles @("include", "src") @(".h", ".hpp", ".cc", ".cpp") @())) '(?<![0-9])1001(?![0-9])')
    Check "C24" "protocol.md §3.2/§3.3：错误码逐值对齐，且不产生保留码 1001" `
        ($codesOk -and ($code1001.Count -eq 0)) `
        ("码表齐备={0}；1001 命中 {1} 处" -f $codesOk, $code1001.Count)

    $eventsOk = ($headerText -match 'onEntityChanged') -and ($headerText -match 'entity\.changed') -and
                ($headerText -match 'target\.state') -and ($headerText -match 'entity\.consistency')
    Check "C25" "protocol.md §4：三个事件的 data 形状有独立类型（entity.changed / target.state / entity.consistency）" `
        $eventsOk "EntityChangeEvent / TargetStateEvent / ConsistencyEvent + IEntitySink 三方法"

    # ================================================================ ⑥ 独立交付
    Section "⑥ 独立交付（ELG-NFR-04：独立构建 / 示例 / 测试 / 验收脚本 / 规则包）"

    $needed = @("CMakeLists.txt", "include\entity_ledger\entity_ledger.h", "src\internal.h",
                "tests\CMakeLists.txt", "tests\selftest.cc", "examples\CMakeLists.txt",
                "examples\minimal\main.cc", "examples\full_flow\main.cc",
                "scripts\acceptance.ps1", "policies\mapapp\entityTypes.json",
                "policies\mapapp\threatFactors.json",
                "tests\fixtures\types-alt.json", "tests\fixtures\actions-alt.json",
                "tests\fixtures\actions-gated.json", "tests\fixtures\bands-shifted.json",
                "tests\fixtures\factors-reweighted.json")
    $absent = @()
    foreach ($f in $needed) { if (-not (Test-Path (Join-Path $script:Repo $f))) { $absent += $f } }
    Check "C27" "独立交付要件齐全（构建 / 公开头 / 测试 / 示例 / 验收脚本 / 规则包 / 夹具）" `
        ($absent.Count -eq 0) ("缺失：{0}" -f (($absent -join ", ") -replace '^$', '无'))

    $exampleCodes = @{}
    foreach ($name in @("example_minimal", "example_consistency")) {
        $exe = Join-Path $bin "$name.exe"
        if (-not (Test-Path $exe)) { $exe = Join-Path $bin $name }
        if (-not (Test-Path $exe)) { $exampleCodes[$name] = -1; continue }
        $out = (& $exe 2>&1 | Out-String)
        $exampleCodes[$name] = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { Write-Host ("    {0} 输出：{1}" -f $name, $out.Trim()) -ForegroundColor DarkGray }
    }
    $exOk = $true
    foreach ($k in $exampleCodes.Keys) { if ($exampleCodes[$k] -ne 0) { $exOk = $false } }
    Check "C28" "两个示例独立运行退出码 0" $exOk `
        (($exampleCodes.Keys | Sort-Object | ForEach-Object { "{0}={1}" -f $_, $exampleCodes[$_] }) -join " ")

    # ⑥ -2 ctest（可选目标，缺 ctest 不判失败）
    $ctest = (Get-Command ctest -ErrorAction SilentlyContinue).Source
    if ($ctest) {
        $ctestOut = (& $ctest --test-dir $buildPath -C $Config --output-on-failure 2>&1 | Out-String)
        $ctestOk = ($LASTEXITCODE -eq 0)
        Check "C29" "ctest 注册的用例全部通过" $ctestOk ((($ctestOut -split "`n") |
            Where-Object { $_ -match 'tests passed|tests failed|Total Test time' }) -join " ")
    } else {
        Check "C29" "ctest 注册的用例全部通过（跳过：未找到 ctest）" $true "ctest 不在 PATH，视为不适用"
    }

    # ⑥ -3 验收脚本自身可机检：以退出码 0/1 结束
    $scriptText = Get-Content -Raw -Encoding UTF8 (Join-Path $script:Repo "scripts\acceptance.ps1")
    $exitOk = ($scriptText -match '(?m)^\s*exit\s+1') -and ($scriptText -match '(?m)^\s*exit\s+0')
    Check "C30" "验收脚本以退出码 0/1 结束（ELG-NFR-04）" $exitOk `
        "脚本内含 exit 0 与 exit 1 两条收口路径"

    # ================================================================ 汇总
    Section "汇总"

    $total = $script:Results.Count
    $passed = 0
    foreach ($r in $script:Results) { if ($r.Ok) { $passed++ } }
    $failed = $total - $passed

    if ($jsonOk) {
        Write-Host ("selftest ：用例 {0} 个（失败 {1}）｜断言 {2} 条（失败 {3}）" -f `
            $data.cases, $data.casesFailed, $data.asserts, $data.assertsFailed)
    }
    Write-Host ("验收检查：{0} 项｜PASS {1}｜FAIL {2}" -f $total, $passed, $failed)

    if ($failed -eq 0) {
        Write-Host ""
        Write-Host "验收通过（退出码 0）" -ForegroundColor Green
        exit 0
    }
    Write-Host ""
    Write-Host "验收失败（退出码 1）：" -ForegroundColor Red
    foreach ($r in $script:Results) {
        if (-not $r.Ok) { Write-Host ("  - {0} {1}：{2}" -f $r.Id, $r.Title, $r.Detail) -ForegroundColor Red }
    }
    exit 1
} finally {
    Pop-Location
}
