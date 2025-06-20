<template>
    <el-form :model="quake" @keydown.enter.native.prevent="tableCtrl.addTab(quake.query, false)">
        <el-form-item>
            <el-autocomplete v-model="quake.query" placeholder="Search..." :fetch-suggestions="syntax.querySearchAsync"
                @select="syntax.handleSelect" :trigger-on-focus="false" :debounce="500" class="w-full">
                <template #prepend>
                    查询条件
                </template>
                <template #suffix>
                    <el-space :size="2">
                        <el-popover placement="bottom-end" :width="700" trigger="click">
                            <template #reference>
                                <div>
                                    <el-tooltip content="语法检索" placement="bottom">
                                        <el-button :icon="CollectionTag" link />
                                    </el-tooltip>
                                </div>
                            </template>
                            <el-tabs v-model="options.keywordActive" class="quake">
                                <el-tab-pane v-for="item in quakeOptions" :name="item.title" :label="item.title">
                                    <el-table :data="item.data" class="keyword-search" @row-click="syntax.rowClick">
                                        <el-table-column width="300" property="key" label="例句">
                                            <template #default="scope">
                                                {{ scope.row.key }}<el-tag type="success" effect="plain"
                                                    v-if="scope.row.isVip" class="ml-5px">VIP</el-tag>
                                            </template>
                                        </el-table-column>
                                        <el-table-column property="description" label="用途说明" />
                                    </el-table>
                                </el-tab-pane>
                            </el-tabs>
                        </el-popover>
                        <el-tooltip content="使用网页图标搜索" placement="bottom">
                            <el-button :icon="PictureRounded" link @click="tableCtrl.searchFavicon" />
                        </el-tooltip>
                        <el-popover placement="bottom-end" :width="400" title="IP/域名批量搜索" trigger="click">
                            <template #reference>
                                <div>
                                    <el-tooltip content="IP/域名批量搜索" placement="bottom">
                                        <!-- 使用el-popover需要增加底部margin 2px才能对其-->
                                        <el-button :icon="Document" link style="margin-bottom: 2px;" />
                                    </el-tooltip>
                                </div>
                            </template>
                            <div class="batch-search">
                                <el-alert type="info" :closable="false" title="上传包含IP/域名的.txt文件，数量不超过1000个" show-icon />
                                <el-button class="upload" :icon="UploadFilled"
                                    @click="UploadFileAndRead(quake, 'batchIps')">上传文件</el-button>
                                <el-input v-model="quake.batchIps" type="textarea" :rows="5"
                                    placeholder="请输入IP/域名，每行一个，多个请换行输入"></el-input>
                                <div class="flex-between">
                                    <div></div>
                                    <el-button color="#4CA87D" :dark="true" class="search"
                                        @click="tableCtrl.addTab(generateRandomString(12), true)">检索</el-button>
                                </div>
                            </div>
                        </el-popover>
                    </el-space>
                    <el-divider direction="vertical" />
                    <el-space :size="2">
                        <el-tooltip content="清空语法" placement="bottom">
                            <el-button :icon="Delete" link @click="quake.query = ''" />
                        </el-tooltip>
                        <el-tooltip content="收藏语法" placement="bottom">
                            <el-button :icon="Star" link @click="syntax.starDialog.value = true" />
                        </el-tooltip>
                        <el-tooltip content="复制语法" placement="bottom">
                            <el-button :icon="DocumentCopy" link @click="Copy(quake.query)" />
                        </el-tooltip>
                        <el-divider direction="vertical" />
                    </el-space>
                    <el-button link :icon="Search" @click="tableCtrl.addTab(quake.query, false)"
                        style="height: 40px;">查询</el-button>
                </template>
                <template #append>
                    <el-space :size="25">
                        <el-popover placement="bottom-end" :width="550" trigger="click">
                            <template #reference>
                                <div>
                                    <el-tooltip content="我收藏的语法" placement="left">
                                        <el-button :icon="Collection" @click="syntax.searchStarSyntax" />
                                    </el-tooltip>
                                </div>
                            </template>
                            <el-table :data="quake.syntaxData" @row-click="syntax.rowClick2" class="keyword-search">
                                <el-table-column width="150" prop="Name" label="语法名称" />
                                <el-table-column prop="Content" label="语法内容" />
                                <el-table-column label="操作" width="100" align="center">
                                    <template #default="scope">
                                        <el-button type="danger" plain size="small" :icon="Delete"
                                            @click="syntax.deleteStar(scope.row.Name, scope.row.Content)">删除
                                        </el-button>
                                    </template>
                                </el-table-column>
                            </el-table>
                        </el-popover>
                    </el-space>
                </template>
                <template #default="{ item }">
                    <div>
                        <span>{{ item.Product_name }}</span>
                        <el-divider direction="vertical" />
                        <span v-if="item.Vendor_name != ''">{{ item.Vendor_name }}</span>
                        <span v-else>-</span>
                        <el-divider direction="vertical" />
                        <el-button link style="color: #4CA87D;">
                            测绘资产数量: {{ item.Ip_count }}
                        </el-button>
                        <el-divider direction="vertical" />
                        <el-button link style="color: #F56C6C;">
                            关联漏洞: {{ item.Vul_count }}
                        </el-button>
                    </div>
                </template>
            </el-autocomplete>
        </el-form-item>
        <el-form-item>
            <div>
                <span class="mr">最新数据</span><el-switch v-model="options.switch.latest"
                    @change="tableCtrl.handleOptionChange" style="--el-switch-on-color: #4CA87D;" />
            </div>
            <el-divider direction="vertical" />
            <div>
                <el-tooltip content="开启后，将过滤掉400、401、502等状态码和无法解析的协议/端口数据" placement="bottom">
                    <span class="mr">过滤无效请求</span>
                </el-tooltip>
                <el-switch v-model="options.switch.invalid" @change="tableCtrl.handleOptionChange"
                    :disabled="quake.certcommon.length == 0" style="--el-switch-on-color: #4CA87D;" />
            </div>
            <el-divider direction="vertical" />
            <div>
                <span class="mr">排除蜜罐</span><el-switch v-model="options.switch.honeypot"
                    :disabled="quake.certcommon.length == 0" @change="tableCtrl.handleOptionChange"
                    style="--el-switch-on-color: #4CA87D;" />
            </div>
            <el-divider direction="vertical" />
            <div>
                <span class="mr">排除CDN</span><el-switch v-model="options.switch.cdn"
                    :disabled="quake.certcommon.length == 0" @change="tableCtrl.handleOptionChange"
                    style="--el-switch-on-color: #4CA87D;" />
            </div>
            <el-divider direction="vertical" />
            <el-input v-model="quake.certcommon" size="small" style="width: 300px;" class="mr">
                <template #prepend>
                    <el-text class="position-center">CertCommon
                        <el-tooltip content="由于排除字段的值为按时间自动生成，请填写网页版登录后的Cookie中的cert_common字段，排除才可正常使用">
                            <el-icon style="margin-left: 2px;">
                                <QuestionFilled />
                            </el-icon>
                        </el-tooltip>
                    </el-text>
                </template>
                <template #suffix>
                    <el-button :icon="ChromeFilled" link @click="openURL('https://quake.360.net/quake/#/index')" />
                </template>
            </el-input>
            <div style="flex-grow: 1;"></div>
            <el-dropdown>
                <el-button :dark="true" text bg style="color: #4CA87D;">
                    更多功能<el-icon class="el-icon--right">
                        <ArrowDown />
                    </el-icon>
                </el-button>
                <template #dropdown>
                    <el-dropdown-menu>
                        <el-dropdown-item :icon="Share" @click="exportData(0)">导出当前查询页数据</el-dropdown-item>
                        <el-dropdown-item :icon="Share" @click="exportData(1)">导出全部数据</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('current', false)" divided>复制当前页URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('top500', false)">复制前500条URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('current', true)" divided>去重复制当前页URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('top500', true)">去重复制前500条URL</el-dropdown-item>
                    </el-dropdown-menu>
                </template>
            </el-dropdown>
        </el-form-item>
    </el-form>
    <el-tabs v-model="table.acvtiveNames" v-loading="table.loading" type="card" closable
        @tab-remove="tableCtrl.removeTab" class="quake-tabs">
        <el-tab-pane v-for="item in table.editableTabs" :key="item.name" :label="item.title" :name="item.name"
            v-if="table.editableTabs.length != 0">
            <el-table :data="item.content" border class="w-full" style="height: calc(100vh - 280px);">
                <el-table-column type="index" fixed label="#" width="60px" />
                <el-table-column prop="URL" fixed label="URL" :min-width="240" :show-overflow-tooltip="true" />
                <el-table-column prop="IP" fixed label="IP" width="160">
                    <template #default="scope">
                        <el-space :size="1">
                            <span>{{ scope.row.IP }}</span>
                            <el-tooltip content="排除检索">
                                <el-button link :icon="ZoomOut" @click="tableCtrl.excludeFiled('ip', scope.row.IP)"></el-button>
                            </el-tooltip>
                        </el-space>
                    </template>
                </el-table-column>
                <el-table-column prop="Port" label="端口/协议" width="130">
                    <template #default="scope">
                        <el-space :size="3">
                            <span>{{ scope.row.Port }}</span>
                            <el-tag type=info round>{{ scope.row.Protocol }}</el-tag>
                        </el-space>
                    </template>
                </el-table-column>
                <el-table-column prop="Host" label="域名" width="150" :show-overflow-tooltip="true">
                    <template #default="scope">
                        <span v-if="scope.row.Host != scope.row.IP">{{ scope.row.Host }}</span>
                        <span v-else>--</span>
                    </template>
                </el-table-column>
                <el-table-column label="网站图标 | 标题" width="250">
                    <template #default="scope">
                        <el-space>
                            <el-image :src="convertHttpToHttps(scope.row.FaviconURL)"
                                @click="tableCtrl.searchFaviconMd5(scope.row.FaviconURL)"
                                style="width: 16px; height: 16px;">
                                <template #error>
                                    <el-icon>
                                        <Picture />
                                    </el-icon>
                                </template>
                            </el-image>
                            <span>{{ scope.row.Title }}</span>
                            <el-tooltip content="排除检索">
                                <el-button v-if="scope.row.Title != ''" link :icon="ZoomOut" @click="tableCtrl.excludeFiled('title', scope.row.Title)" style="margin-left: -7px;"></el-button>
                            </el-tooltip>
                        </el-space>
                    </template>
                </el-table-column>
                <el-table-column prop="Component" label="产品应用/版本" width="260">
                    <template #default="scope">
                        <el-button type="success" plain size="small"
                            v-if="Array.isArray(scope.row.Components) && scope.row.Components.length > 0">
                            <template #icon v-if="scope.row.Components.length > 1">
                                <el-popover placement="bottom" :width="350" trigger="hover">
                                    <template #reference>
                                        <el-icon>
                                            <Histogram />
                                        </el-icon>
                                    </template>
                                    <el-space direction="vertical">
                                        <el-tag round type="success" v-for="component in scope.row.Components"
                                            style="width: 320px;">
                                            {{ component }}</el-tag>
                                    </el-space>
                                </el-popover>
                            </template>
                            {{ scope.row.Components[0] }}
                        </el-button>
                    </template>
                </el-table-column>
                <el-table-column prop="IcpName" label="备案名称" width="160" :show-overflow-tooltip="true" />
                <el-table-column prop="IcpNumber" label="备案号" width="160" :show-overflow-tooltip="true" />
                <el-table-column prop="CertName" label="证书申请单位" width="160" :show-overflow-tooltip="true" />
                <el-table-column prop="Isp" label="运营商" width="100" :show-overflow-tooltip="true" />
                <el-table-column prop="Position" label="地理位置" width="200" :show-overflow-tooltip="true" />
                <el-table-column fixed="right" label="操作" width="120" align="center">
                    <template #default="scope">
                        <el-tooltip content="打开链接" placement="top">
                            <el-button link :icon="ChromeFilled" @click="openURL(scope.row.URL)" />
                        </el-tooltip>
                        <el-divider direction="vertical" />
                        <el-tooltip content="C段查询" placement="top">
                            <el-button link :icon="csegmentIcon"
                                @click.prevent="tableCtrl.addTab('ip: ' + CsegmentIpv4(scope.row.IP), false)">
                            </el-button>
                        </el-tooltip>
                        <el-divider direction="vertical" />
                        <el-tooltip content="证书查询" placement="top">
                            <el-button link :icon="certIcon" @click="tableCtrl.searchCert(scope.row.CertName)" />
                        </el-tooltip>
                    </template>
                </el-table-column>
            </el-table>
            <div class="flex-between mt-10px">
                <span style="color: #4CA87D; font-size: 14px;">{{ item.message }}</span>
                <el-pagination size="small" class="quake-pagin" background v-model:page-size="item.pageSize"
                    :page-sizes="[10, 20, 50, 100, 200, 500]" layout="total, sizes, prev, pager, next, jumper"
                    @size-change="tableCtrl.handleSizeChange" @current-change="tableCtrl.handleCurrentChange"
                    :total="item.total" />
            </div>
        </el-tab-pane>
        <el-empty v-else></el-empty>
    </el-tabs>
    <el-dialog v-model="syntax.starDialog.value" title="收藏语法" width="40%" center>
        <!-- 一定要用:model v-model校验会失效 -->
        <el-form ref="ruleFormRef" :model="syntax.ruleForm" :rules="global.syntaxRules" status-icon>
            <el-form-item label="语法名称" prop="Name">
                <el-input v-model="syntax.ruleForm.Name" maxlength="30" show-word-limit></el-input>
            </el-form-item>
            <el-form-item label="语法内容" prop="Content">
                <el-input v-model="syntax.ruleForm.Content" type="textarea" :rows="10" maxlength="1024"
                    show-word-limit></el-input>
            </el-form-item>
            <el-form-item class="align-right">
                <el-button color="#4CA87D" :dark="true" style="color: #fff;" @click="syntax.submitStar(ruleFormRef)">
                    确定
                </el-button>
                <el-button @click="syntax.starDialog.value = false">取消</el-button>
            </el-form-item>
        </el-form>
    </el-dialog>
</template>

<script lang="ts" setup>
import { Search, ArrowDown, DocumentCopy, Document, PictureRounded, Histogram, UploadFilled, Delete, Star, Collection, CollectionTag, ChromeFilled, QuestionFilled, Picture, ZoomOut, Share } from '@element-plus/icons-vue';
import { reactive, ref } from 'vue';
import { Copy, ReadLine, generateRandomString, splitInt, transformArrayFields, CsegmentIpv4, UploadFileAndRead, convertHttpToHttps, openURL } from '@/util';
import { ExportToXlsx } from '@/export';
import { QuakeTableTabs, QuakeTipsData } from '@/stores/interface';
import { FaviconMd5, QuakeSearch, QuakeTips } from 'wailsjs/go/services/App';
import global from '@/stores';
import { ElMessage, ElMessageBox, ElNotification, FormInstance } from 'element-plus';
import { FileDialog } from 'wailsjs/go/services/File';
import { InsertFavGrammarFiled, RemoveFavGrammarFiled, SelectAllSyntax } from 'wailsjs/go/services/Database';
import csegmentIcon from '@/assets/icon/csegment.svg'
import certIcon from '@/assets/icon/cert.svg'
import { structs } from 'wailsjs/go/models';
import { quakeOptions } from '@/stores/options';

const options = ({
    keywordActive: "基本信息",
    switch: reactive({
        latest: true,
        invalid: false,
        honeypot: false,
        cdn: false,
    }),
})

const ruleFormRef = ref<FormInstance>()

const syntax = ({
    querySearchAsync: (queryString: string, cb: Function) => {
        if (queryString.includes(":") || !queryString) {
            cb(quake.tips)
            return
        }
        syntax.getTips(queryString)
        cb(quake.tips);
    },
    getTips: async function (queryString: string) {
        quake.tips = []
        let result = await QuakeTips(queryString)
        if (result.code != 0) {
            return
        }
        for (const item of result.data!) {
            quake.tips.push({
                Product_name: item.product_name,
                Vul_count: item.vul_count,
                Vendor_name: item.vendor_name,
                Ip_count: item.ip_count,
            })
        }
    },
    handleSelect: (item: Record<string, any>) => {
        quake.query = `app:"${item.Product_name}"`
    },
    rowClick: function (row: any, column: any, event: Event) {
        if (quake.query == "") {
            quake.query = row.key
            return
        }
        quake.query += " AND " + row.key
    },
    rowClick2: function (row: any, column: any, event: Event) {
        if (quake.query == "") {
            quake.query = row.Content
            return
        }
        quake.query += " AND " + row.Content
    },
    starDialog: ref(false),
    ruleForm: reactive<structs.SpaceEngineSyntax>({
        Name: '',
        Content: '',
    }),
    createStarDialog: () => {
        syntax.starDialog.value = true
        syntax.ruleForm.Name = ""
        syntax.ruleForm.Content = quake.query
    },
    submitStar: async (formEl: FormInstance | undefined) => {
        if (!formEl) return
        let result = await formEl.validate()
        if (!result) return
        InsertFavGrammarFiled("quake", syntax.ruleForm.Name!, syntax.ruleForm.Content!).then((r: Boolean) => {
            if (r) {
                ElMessage.success('添加语法成功')
            } else {
                ElMessage.error('添加语法失败')
            }
            syntax.starDialog.value = false
        })
    },
    deleteStar: (name: string, content: string) => {
        RemoveFavGrammarFiled("quake", name, content).then((r: Boolean) => {
            if (r) {
                ElMessage.success('删除语法成功,重新打开刷新')
            } else {
                ElMessage.error('删除语法失败')
            }
        })
    },
    searchStarSyntax: async () => {
        quake.syntaxData = await SelectAllSyntax("quake")
    },
})

const quake = reactive({
    query: '',
    tips: [] as QuakeTipsData[],
    iconURL: "",
    iconFile: "",
    batchIps: "",
    batchFile: "",
    syntaxData: [] as structs.SpaceEngineSyntax[],
    certcommon: "",
})

const table = reactive({
    acvtiveNames: "1",
    tabIndex: 1,
    editableTabs: [] as QuakeTableTabs[],
    loading: false,
})

const tableCtrl = ({
    addTab: async (query: string, isBatch: boolean) => {
        if (!query) {
            ElMessage.warning("请输入查询语句")
            return
        }
        const newTabName = `${++table.tabIndex}`
        let ipList = [] as string[]
        if (isBatch) {
            ipList = await tableCtrl.getIpList()
            if (ipList.length > 1000) {
                ElMessage.warning("批量检索数量不能超过1000个目标!")
                return
            }
        }
        table.loading = true
        let result = await QuakeSearch(ipList, query, 1, 10, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            ElMessage.warning(result.Message)
            table.loading = false
            return
        }
        table.editableTabs.push({
            title: query,
            name: newTabName,
            content: [] as structs.QuakeData[],
            total: 0,
            pageSize: 10,
            currentPage: 1,
            isBatch: isBatch,
            ipList: ipList,
            message: "查询成功,目前剩余积分:" + result.Credit
        });
        table.acvtiveNames = newTabName
        const tab = table.editableTabs.find(tab => tab.name === newTabName)!;
        tab.content = result.Data
        tab.total = result.Total!
        table.loading = false
    },
    removeTab: (targetName: string) => {
        const tabs = table.editableTabs
        let activeName = table.acvtiveNames
        if (activeName === targetName) {
            tabs.forEach((tab, index) => {
                if (tab.name === targetName) {
                    tab.content = [] // 清理内存
                    const nextTab = tabs[index + 1] || tabs[index - 1]
                    if (nextTab) {
                        activeName = nextTab.name
                    }
                }
            })
        }
        table.acvtiveNames = activeName
        table.editableTabs = tabs.filter((tab) => tab.name !== targetName)
    },
    handleSizeChange: async (val: any) => {
        const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
        tab.pageSize = val
        tab.currentPage = 1
        table.loading = true
        let result = await QuakeSearch(tab.ipList, tab.title, 1, tab.pageSize, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            tab.message = result.Message
            table.loading = false
            return
        }
        tab.message = "查询成功,目前剩余积分:" + result.Credit
        tab.content = result.Data
        tab.total = result.Total!
        table.loading = false
    },
    handleCurrentChange: async (val: any) => {
        const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
        tab.currentPage = val
        table.loading = true
        let result = await QuakeSearch(tab.ipList, tab.title, tab.currentPage, tab.pageSize, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            tab.message = result.Message
            table.loading = false
            return
        }
        tab.message = "查询成功,目前剩余积分:" + result.Credit
        tab.content = result.Data
        tab.total = result.Total!
        table.loading = false
    },
    handleOptionChange: async () => {
        const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
        tab.pageSize = 10
        tab.currentPage = 1
        table.loading = true
        let result = await QuakeSearch(tab.ipList, tab.title, 1, tab.pageSize, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            tab.message = result.Message
            table.loading = false
            return
        }
        tab.message = "查询成功,目前剩余积分:" + result.Credit
        tab.content = result.Data
        tab.total = result.Total!
        table.loading = false
    },
    searchFavicon: function () {
        ElMessageBox.prompt('输入目标Favicon地址会自动计算并搜索相关资产', '图标搜索', {
            confirmButtonText: '查询',
            inputPattern: /^(https?:\/\/)?((([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})|localhost|(\d{1,3}\.){3}\d{1,3})(:\d+)?(\/[^\s]*)?$/,
            inputErrorMessage: 'Invalid URL',
            showCancelButton: false,
        })
            .then(async ({ value }) => {
                let hash = await FaviconMd5(value.trim())
                if (!hash) {
                    ElNotification.warning("目标不可达或者URL格式错误");
                    return
                }
                tableCtrl.addTab(`favicon:${hash}`, false);
            }).catch(() => {
            })
    },
    searchCert: function (certName: string) {
        if (certName == "") {
            return
        }
        tableCtrl.addTab(`cert: "${certName}"`, false)
    },
    searchFaviconMd5: function (url: string) {
        if (url == "") {
            return
        }
        let md5 = getLastPathSegment(url)
        tableCtrl.addTab("favicon:" + md5, false)
    },
    excludeFiled: function (filedName: "title" | "ip", filedValue: string) {
        if (filedValue == "") {
            return
        }
        const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
        quake.query = `${tab.title} AND NOT (${filedName}: "${filedValue.trim()}")`
        tableCtrl.addTab(quake.query, false)
    },
    // type 0 choose txt , type 1 choose img
    handleFileupload: async function (type: number) {
        if (type == 0) {
            quake.iconFile = await FileDialog("")
        } else {
            quake.batchFile = await FileDialog("*.txt")
            quake.batchIps = (await ReadLine(quake.batchFile))!.join("\n")
        }
    },
    getIpList: async function () {
        let ips = quake.batchIps.split("\n")
        if (ips.length > 1000) {
            ElMessage.warning("最多支持1000个IP")
            return []
        }
        return ips
    },
})

async function copyURLs(type: 'current' | 'top500', dedup: boolean = false) {
    if (table.editableTabs.length == 0) {
        ElNotification.warning({
            title: "Quake Tips",
            message: "请先进行数据查询",
        })
        return
    }
    const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
    let urls: string[] = [];
    if (type === 'current') {
        let data = tab.content!;
        if (dedup) {
            const seen = new Set();
            data = data.filter(item => {
                const key = `${item.IP}_${item.Title}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }
        urls = data.map(item => item.URL);
    } else {
        let result = await QuakeSearch(tab.ipList, tab.title, 1, 500, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            ElNotification.error({
                title: "Quake Tips",
                message: `${tab.title} 在查询数据时遇到错误: ${result.Message}`,
            })
            return
        }
        let data = result.Data;
        if (dedup) {
            const seen = new Set();
            data = data.filter(item => {
                const key = `${item.IP}_${item.Title}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }

        urls = data.map(item => item.URL);
    }

    Copy(urls.join("\n"));
}

function getLastPathSegment(url: string): string | null {
    const urlObj = new URL(url);  // 创建 URL 对象
    const pathSegments = urlObj.pathname.split('/');  // 按斜杠分割路径
    return pathSegments.length > 0 ? pathSegments[pathSegments.length - 1] : null;  // 返回最后一个部分
}

const excelHeaders = ["URL", "应用/组件", "端口", "协议", "域名", "标题", "单位名称", "备案号", "证书申请单位", "Logo", "IP", "运营商", "地理位置"]
async function exportData(mode: number) {
    if (table.editableTabs.length == 0) {
        ElNotification.warning({
            title: "Quake Tips",
            message: "请先进行数据查询",
        })
        return
    }
    const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;

    if (mode == 0 || tab.total <= tab.pageSize) {
        ExportToXlsx(excelHeaders, "asset", "quake_asset", transformArrayFields(tab.content))
        return
    }

    if (tab.total > 500) {
        ElNotification.info({
            title: "Quake Tips",
            message: "正在进行全数据导出, API每页最大查询限度500, 请稍后。",
        });
    }
    let ipList = [] as string[]
    let temp = [] as structs.QuakeData[]
    if (tab.isBatch) {
        ipList = await tableCtrl.getIpList()
    }
    let index = 0
    for (const num of splitInt(tab.total, 500)) {
        index += 1
        ElMessage("正在查询第" + index.toString() + "页");
        let result = await QuakeSearch(ipList, tab.title, index, num, options.switch.latest, options.switch.invalid, options.switch.honeypot, options.switch.cdn, global.space.quakekey, quake.certcommon)
        if (result.Code != 0) {
            ElNotification.error({
                title: "Quake Tips",
                message: `${tab.title} 导出数据时遇到错误: ${result.Message}, 当前查询到第${index}页`,
            })
            table.loading = false
            break
        }
        temp.push(...result.Data)
    }
    ExportToXlsx(excelHeaders, "asset", "quake_asset", transformArrayFields(temp))
    temp = []
}
</script>

<style scoped>
.el-image:hover {
    cursor: pointer;
}

.keyword-search :deep(.el-table__row:hover) {
    color: #4CA87D;
    cursor: pointer;
}

.quake :deep(.el-tabs__nav-scroll) {
    display: flex;
    justify-content: center;
    align-items: center;
}

.quake :deep(.el-tabs__item:hover) {
    color: #4CA87D;
}

.quake :deep(.el-tabs__item.is-active) {
    color: #4CA87D;
    /* 文本颜色 */
}

.quake :deep(.el-tabs__active-bar) {
    background-color: #4CA87D;
}

.el-alert .--el-alert-icon-large-size {
    width: 16px;
}

.batch-search {
    display: flex;
    flex-direction: column;
    gap: 8px;

    .upload {
        height: 50px;
        width: 100%;
        border-style: dashed;
        color: #4CA87D;
    }

    .search {
        color: #fff;
        width: 20%;
    }

    .search:hover {
        color: #fff;
    }
}

.mr {
    margin-right: 10px;
}

.quake-tabs :deep(.el-tabs__item) {
    position: relative;
    display: inline-block;
    max-width: 300px;
    margin-bottom: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    padding-right: 26px !important;
    /* 给关闭按钮预留空间 */
}

.quake-tabs :deep(.el-tabs__item:hover) {
    color: #4CA87D;
    cursor: pointer;
}

.quake-tabs :deep(.el-tabs__item .el-icon) {
    position: absolute !important;
    top: 13px !important;
    right: 7px !important;
}

.quake-tabs :deep(.el-tabs__nav) {
    line-height: 255%;
}

.quake-tabs :deep(.el-tabs__item.is-active) {
    color: #4CA87D;
}

.quake-pagin :deep(.el-pager li.is-active) {
    background-color: #4CA87D;
}

.quake-pagin :deep(.el-pager li.is-active:hover) {
    color: #fff;
}

.quake-pagin :deep(.el-pager li:hover) {
    color: #4CA87D;
}

.quake-pagin :deep(.el-select-dropdown__item.is-selected) {
    color: #4CA87D;
    font-weight: bold;
}
</style>