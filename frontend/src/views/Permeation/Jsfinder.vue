<script lang="ts" setup>
import { onMounted, reactive, ref } from 'vue';
import { Copy, parseHeaders, ProcessTextAreaInput } from '@/util';
import { AnalyzeAPI, ExtractAllJSLink, JSFind, GoFetch } from 'wailsjs/go/services/App';
import { ArrowUpBold, ArrowDownBold, Delete, DocumentCopy, Share } from '@element-plus/icons-vue';
import global from "@/stores";
import { ElNotification, ElMessage } from 'element-plus';
import CustomTextarea from '@/components/CustomTextarea.vue';
import saveIcon from '@/assets/icon/save.svg'
import usePagination from '@/usePagination';
import { JSFindOptions } from '@/stores/options';
import { BrowserOpenURL, EventsOff, EventsOn } from 'wailsjs/runtime/runtime';
import { getTagTypeBySeverity } from '@/stores/style';
import { SaveConfig } from '@/config';
import { structs } from 'wailsjs/go/models';
import { ExportJSReportWithExcel } from 'wailsjs/go/services/Database';
import { SaveFileDialog } from 'wailsjs/go/services/File';

onMounted(() => {
    // 初始化参数
    config.blackList = global.jsfinder.whiteList.join("\n");
    config.authFiled = global.jsfinder.authFiled.join("\n");
    config.highRiskRouter = global.jsfinder.highRiskRouter.join("\n");

    EventsOn("jsfindlog", (msg: any) => {
        config.consoleLog += msg + "\n";
    });
    EventsOn("jsfindvulcheck", (result: any) => {
        pagination.table.result.push({
            Target: "",
            Method: result.Method,
            Source: result.Source,
            VulType: result.VulType,
            Severity: "HIGH",
            Request: result.Request,
            Length: result.Length,
            Filed: "",
            Response: result.Response,
        })
        pagination.ctrl.watchResultChange(pagination.table)
    });
    return () => {
        EventsOff("jsfindlog");
        EventsOff("webFingerScan");
    };
})

const value = ref(0)

const config = reactive({
    urls: "",
    loading: false,
    otherURL: false,
    prefixApiURL: '',
    prefixJsURL: '',
    headers: '',
    lowHeaders: '',
    consoleLog: '',
    authFiled: '',
    highRiskRouter: '',
    blackList: '',
})

const pagination = usePagination<structs.JSFindResult>(20)

async function JSFinder() {
    let urls = ProcessTextAreaInput(config.urls)
    if (urls.length == 0) {
        ElMessage.warning("可用目标为空");
        return
    }
    showForm.value = false
    config.loading = true
    pagination.initTable()
    config.consoleLog = ""
    for (const url of urls) {
        let apiRoute = [] as string[]
        config.consoleLog += `[*] 正在提取${url}的JS链接\n`
        let jslinks = await ExtractAllJSLink(url)
        config.consoleLog += `[+] 共提取到JS链接: ${getLength(jslinks)}个\n`
        if (jslinks != null) {
            config.consoleLog += jslinks.join("\n")
        }
        config.consoleLog += "\n\n[*] 正在提取JS信息中\n"
        let somethings = await JSFind(url, config.prefixJsURL, jslinks, global.jsfinder.whiteList)
        config.consoleLog += `[+] 共提取到API: ${getLength(somethings.APIRoute)}个\n`
        somethings.APIRoute.forEach(item => {
            apiRoute.push(item.Filed)
            config.consoleLog += `${item.Filed}\n`
        })
        config.consoleLog += "\n\n"
        config.consoleLog += `[+] 共提取到身份证: ${getLength(somethings.IDCard)}个\n`
        somethings.IDCard.forEach(item => {
            config.consoleLog += `${item.Filed} [ Source: ${item.Source} ]\n`
            pagination.table.result.push({
                Source: item.Source,
                Method: "GET",
                Filed: item.Filed,
                VulType: "身份证号信息泄露",
                Severity: "MEDIUM",
                Length: 0,
                Request: "",
                Target: url,
                Response: "",
            })
            pagination.ctrl.watchResultChange(pagination.table)
        })
        config.consoleLog += "\n\n"
        config.consoleLog += `[+] 共提取到手机号: ${getLength(somethings.Phone)}个\n`
        somethings.Phone.forEach(item => {
            config.consoleLog += `${item.Filed} [ Source: ${item.Source} ]\n`
            pagination.table.result.push({
                Source: item.Source,
                Method: "GET",
                Filed: item.Filed,
                VulType: "手机号信息泄露",
                Severity: "LOW",
                Length: 0,
                Request: "",
                Target: url,
                Response: "",
            })
            pagination.ctrl.watchResultChange(pagination.table)
        })
        config.consoleLog += "\n\n"
        config.consoleLog += `[+] 共提取到邮箱: ${getLength(somethings.Email)}个\n`
        if (somethings.Email) {
            const emails = somethings.Email.map(item => item.Filed)
            config.consoleLog += emails.join("\n")
        }
        config.consoleLog += "\n\n"
        if (somethings.Sensitive) {
            config.consoleLog += `[+] 共提取到敏感字段: ${getLength(somethings.Sensitive)}个\n`
            somethings.Sensitive.forEach(item => {
                config.consoleLog += `${item.Filed} [ Source: ${item.Source} ]\n`
                pagination.table.result.push({
                    Source: item.Source,
                    Method: "GET",
                    Filed: item.Filed,
                    VulType: "敏感字段泄露",
                    Severity: "INFO",
                    Length: 0,
                    Request: "",
                    Target: url,
                    Response: "",
                })
                pagination.ctrl.watchResultChange(pagination.table)
            })
        }
        config.consoleLog += "\n\n"
        if (somethings.IP_URL && somethings.IP_URL.length > 0) {
            const filteredIPs = somethings.IP_URL
                .filter(item => !global.jsfinder.whiteList.some(black => item.Filed.includes(black))) // 过滤黑名单
                .map(item => item.Filed); // 提取字段

            if (filteredIPs.length > 0) {
                config.consoleLog += `[+] 共提取到IP/URL: ${filteredIPs.length}个\n` + filteredIPs.join("\n") + "\n";
            }
        }
        config.consoleLog += "\n\n"
        config.consoleLog += "[*] 正在分析API漏洞中...\n"
        let baseURL = ""

        config.prefixApiURL != "" ? baseURL = config.prefixApiURL : baseURL = url

        await AnalyzeAPI(url, baseURL, apiRoute, parseHeaders(config.headers), parseHeaders(config.lowHeaders), global.jsfinder.authFiled, global.jsfinder.highRiskRouter)
    }
    config.consoleLog += "[*] 任务运行结束\n"
    config.loading = false
    ElNotification.success({
        message: "JSFinder 任务已完成",
        position: "bottom-right",
    });
}

function getLength(arr: any) {
    if (Array.isArray(arr)) {
        return arr.length;
    } else {
        return 0;
    }
}

const showForm = ref(true);

function toggleFormVisibility() {
    showForm.value = !showForm.value;
}

const dialog = ref(false);
const detail = reactive({
    Target: '',
    Method: '',
    Source: '',
    VulType: '',
    Severity: '',
    Request: '',
    Filed: '',
    Response: '',
});
function openDialog(row: any) {
    dialog.value = true;
    detail.Target = row.Target;
    detail.Method = row.Method;
    detail.Source = row.Source;
    detail.VulType = row.VulType;
    detail.Severity = row.Severity;
    detail.Request = row.Request;
    detail.Filed = row.Filed;
    detail.Response = row.Response;
}

const authURL = "https://gitee.com/the-temperature-is-too-low/Slack/raw/main/jsfinder-auth"
async function FetchDiffrerentAuth() {
    let response = await GoFetch("GET", authURL, "", null, 10, null)
    if (response.Error) {
        ElMessage.error("远程拉取失败")
        return
    }
    let remoteAuth = ProcessTextAreaInput(response.Body)
    let diffAuth = findMissingElements(global.jsfinder.authFiled, remoteAuth)
    if (diffAuth.length == 0) {
        ElMessage.info("已是最新配置, 无需同步")
        return
    }
    let mergedAuth = Array.from(new Set([...global.jsfinder.authFiled, ...remoteAuth]));
    config.authFiled = mergedAuth.join("\n")
    ElMessage.success("差异化同步成功")
}

function saveConfig() {
    global.jsfinder.authFiled = ProcessTextAreaInput(config.authFiled)
    global.jsfinder.highRiskRouter = ProcessTextAreaInput(config.highRiskRouter)
    global.jsfinder.whiteList = ProcessTextAreaInput(config.blackList)
    SaveConfig()
}

function findMissingElements(A: string[], B: string[]) {
    let setA = new Set(A);
    return B.filter(item => !setA.has(item));
}

async function exportData() {
    let filepath = await SaveFileDialog("JSFinder-Report.xlsx")
    if (!filepath) {
        return
    }
    let isSuccess = await ExportJSReportWithExcel(filepath, pagination.table.result)
    isSuccess ? ElMessage.success("导出成功") : ElMessage.error("导出失败")
}
</script>

<template>
    <el-divider>
        <el-button round :icon="showForm ? ArrowUpBold : ArrowDownBold" @click="toggleFormVisibility"
            v-if="!config.loading">
            {{ showForm ? '隐藏参数' : '展开参数' }}
        </el-button>
        <el-button round loading v-else>正在运行</el-button>
    </el-divider>
    <el-collapse-transition>
        <div class="flex gap-2" v-show="showForm">
            <el-form :model="config" label-width="auto" class="w-1/2">
                <el-form-item label="目标地址:">
                    <CustomTextarea v-model="config.urls" :rows="5" />
                    <span class="form-item-tips">需要输入应用目录根路径</span>
                </el-form-item>
                <el-form-item label="JS前缀:">
                    <el-input v-model="config.prefixJsURL" />
                    <span class="form-item-tips">部分二级路径采集的JS无法准确拼接时, 自定义路径前缀</span>
                </el-form-item>
                <el-form-item label="路径前缀:">
                    <el-input v-model="config.prefixApiURL" />
                    <span class="form-item-tips">默认将获取到的API拼接到目标地址中, 大部分API需要都拼接在接口路径, 需要自行获取</span>
                </el-form-item>
                <el-form-item label="正常请求头:">
                    <el-input v-model="config.headers" type="textarea" :rows="5" />
                </el-form-item>
                <el-form-item label="低权限请求头:">
                    <el-input v-model="config.lowHeaders" type="textarea" :rows="5" />
                    <span class="form-item-tips"><el-tag type="danger" class="mr-5px">beta</el-tag>该参数用于判断接口是否存在越权漏洞, 会将原有的请求头中的同字段键的值进行替换, 换行分割</span>
                </el-form-item>
            </el-form>
            <el-form :model="config" label-width="auto" class="w-1/2">
                <el-form-item label="鉴权字段:">
                    <el-input v-model="config.authFiled" type="textarea" :rows="5"></el-input>
                    <span class="form-item-tips">判断内容响应体是否需要鉴权</span>
                    <el-button type="primary" link size="small" @click="FetchDiffrerentAuth()">远程拉取, 差异化同步</el-button>
                </el-form-item>
                <el-form-item label="高危路由:">
                    <el-input v-model="config.highRiskRouter" type="textarea" :rows="5"></el-input>
                    <span class="form-item-tips">在API中匹配路由关键词, 匹配成功会跳过接口测试</span>
                </el-form-item>
                <el-form-item label="黑名单域名:">
                    <el-input v-model="config.blackList" type="textarea" :rows="5"></el-input>
                    <span class="form-item-tips">黑名单的JS内容不会进行信息采集</span>
                </el-form-item>
                <el-form-item label=" ">
                    <el-button type="primary" @click="JSFinder">开始任务</el-button>
                    <el-button :icon="saveIcon" @click="saveConfig()">保存配置</el-button>
                </el-form-item>
            </el-form>
        </div>
    </el-collapse-transition>
    <el-card shadow="never" class="mb-10px">
        <template #header>
            <div class="card-header">
                <el-segmented v-model="value" :options="JSFindOptions">
                    <template #default="{ item }">
                        <el-space :size="3">
                            <el-icon>
                                <component :is="item.icon" />
                            </el-icon>
                            <div>{{ item.label }}</div>
                        </el-space>
                    </template>
                </el-segmented>
                <span>发现风险数: {{ pagination.table.result.length }}</span>
                <div v-show="value == 0">
                    <el-button :icon="DocumentCopy" link @click="Copy(config.consoleLog)" />
                    <el-button :icon="Delete" link @click="config.consoleLog = ''" />
                </div>
            </div>
        </template>
        <pre class="pretty-response" v-show="value == 0"><code>{{ config.consoleLog }}</code></pre>
        <el-table :data="pagination.table.pageContent" 
            :highlight-current-row="true"
            style="height: calc(100vh - 200px)"
            @sort-change="pagination.ctrl.sortChange" v-show="value == 1">
            <el-table-column label="INFO">
                <template #default="scope">
                    <el-space>
                        <el-tag type="info">{{ scope.row.Method }}</el-tag>
                        <el-tag type="info">{{ scope.row.Source }}</el-tag>
                        <el-tag type="warning" v-if="scope.row.Filed != ''">{{ scope.row.Filed }}</el-tag>
                    </el-space>
                </template>
            </el-table-column>
            <el-table-column prop="Length" label="Length" width="150" sortable="custom" />
            <el-table-column prop="VulType" label="Vulnerability" column-key="Severity" width="300">
                <template #filter-icon>
                    <Filter />
                </template>
                <template #default="scope">
                    <el-space>
                        <el-tag :type="getTagTypeBySeverity(scope.row.Severity)">
                            {{ scope.row.Severity }}
                        </el-tag>
                        <span>{{ scope.row.VulType }}</span>
                    </el-space>
                </template>
            </el-table-column>
            <el-table-column width="120" align="center">
                <template #header>
                    <el-button :icon="Share" size="small" @click="exportData">导出数据</el-button>
                </template>
                <template #default="scope">
                    <el-button type="primary" @click="openDialog(scope.row)">More</el-button>
                </template>
            </el-table-column>
            <template #empty>
                <el-empty />
            </template>
        </el-table>
        <div class="flex-between mt-5px" v-show="value == 1">
            <div></div>
            <el-pagination size="small" background @size-change="pagination.ctrl.handleSizeChange"
                @current-change="pagination.ctrl.handleCurrentChange" :pager-count="5"
                :current-page="pagination.table.currentPage" :page-sizes="[10, 20, 50, 100]"
                :page-size="pagination.table.pageSize" layout="total, sizes, prev, pager, next"
                :total="pagination.table.result.length">
            </el-pagination>
        </div>
    </el-card>
    <el-dialog v-model="dialog" title="漏洞详情">
        请求方式: {{ detail.Method }} <br /><br />
        <span>源目标: <el-link type="primary" @click="BrowserOpenURL(detail.Target)">{{
            detail.Target }}</el-link> <br /><br /></span>
        来源链接: <el-link type="primary" @click="BrowserOpenURL(detail.Source)">{{ detail.Source }}</el-link><br /><br />
        漏洞类型: {{ detail.VulType }} <br /><br />
        <span>字段内容: {{ detail.Filed }}<br /><br /></span>
        漏洞等级: <el-tag :type="getTagTypeBySeverity(detail.Severity)">
            {{ detail.Severity }}
        </el-tag> <br /><br />
        <span>请求内容: </span>
        <pre style="white-space: pre-wrap; word-break: break-all;"><code>{{ detail.Request }}</code></pre>
        <br />
        <span>响应内容: </span><br />
        <code>{{ detail.Response }}</code>
    </el-dialog>
</template>

<style scoped></style>