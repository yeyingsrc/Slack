<script setup lang="ts">
import { ExportToXlsx } from '@/export'
import { reactive, ref } from 'vue';
import { ElNotification, ElMessage, ElMessageBox, FormInstance } from "element-plus";
import { Search, ChromeFilled, DocumentCopy, PictureRounded, Delete, Star, Collection, CollectionTag, Share } from '@element-plus/icons-vue';
import { splitInt, Copy, CsegmentIpv4, openURL } from '@/util'
import { TableTabs, HunterEntryTips } from "@/stores/interface"
import global from "@/stores"
import { FaviconMd5, HunterSearch, HunterTips } from 'wailsjs/go/services/App'
import { InsertFavGrammarFiled, SelectAllSyntax, RemoveFavGrammarFiled } from 'wailsjs/go/services/Database'
import csegmentIcon from '@/assets/icon/csegment.svg'
import { hunterOptions } from '@/stores/options';
import { structs } from 'wailsjs/go/models';

// ref得单独校验
const ruleFormRef = ref<FormInstance>()

const syntax = ({
    starDialog: ref(false),
    ruleForm: reactive<structs.SpaceEngineSyntax>({
        Name: '',
        Content: '',
    }),
    createStarDialog: () => {
        syntax.starDialog.value = true
        syntax.ruleForm.Name = ""
        syntax.ruleForm.Content = form.query
    },
    submitStar: async (formEl: FormInstance | undefined) => {
        if (!formEl) return
        let result = await formEl.validate()
        if (!result) return
        InsertFavGrammarFiled("hunter", syntax.ruleForm.Name!, syntax.ruleForm.Content!).then((r: Boolean) => {
            if (r) {
                ElMessage.success('添加语法成功')
            } else {
                ElMessage.error('添加语法失败')
            }
            syntax.starDialog.value = false
        })
    },
    deleteStar: (name: string, content: string) => {
        RemoveFavGrammarFiled("hunter", name, content).then((r: Boolean) => {
            if (r) {
                ElMessage.success('删除语法成功,重新打开刷新')
            } else {
                ElMessage.error('删除语法失败')
            }
        })
    },
    searchStarSyntax: async () => {
        form.syntaxData = await SelectAllSyntax("hunter")
    },
})

const form = reactive({
    query: '',
    defaultTime: '0',
    defaultSever: '3',
    keywordActive: "IP",
    deduplication: false,
    batchdialog: false,
    batchURL: '',
    syntaxData: [] as structs.SpaceEngineSyntax[],
})

const entry = ({
    querySearchAsync: async (queryString: string, cb: Function) => {
        if (queryString.includes("=") || !queryString) {
            cb([]);
            return
        }
        let tips = await entry.getTips(queryString)
        cb(tips);
    },
    getTips: async function (queryString: string) {
        let result = await HunterTips(queryString)
        let tips = [] as HunterEntryTips[]
        if (result.code == 200) {
            for (const item of result.data.app) {
                tips.push({
                    value: item.name,
                    assetNum: item.asset_num,
                    tags: item.tags
                })
            }
        }
        return tips
    },
    handleSelect: (item: Record<string, any>) => {
        form.query = `app.name="${item.value}"`
    },
    rowClick: function (row: any, column: any, event: Event) {
        if (!form.query) {
            form.query = row.key
            return
        }
        form.query += " && " + row.key
    },
    rowClick2: function (row: any, column: any, event: Event) {
        if (!form.query) {
            form.query = row.Content
            return
        }
        form.query += " && " + row.Content
    },
})

const table = reactive({
    acvtiveNames: "1",
    tabIndex: 1,
    editableTabs: [] as TableTabs[],
    loading: false,
})

const tableCtrl = ({
    addTab: async (query: string) => {
        if (!global.space.hunterkey) {
            ElNotification.warning("请在设置处填写Hunter Key")
            return
        }
        if (query == "") {
            ElNotification.warning("请输入查询内容")
            return
        }
        const newTabName = `${++table.tabIndex}`
        table.loading = true
        let result = await HunterSearch(global.space.hunterapi, global.space.hunterkey, query, "10", "1", form.defaultTime, form.defaultSever, form.deduplication)
        if (isError(result.code, result.message)) {
            table.loading = false
            return
        }
        table.editableTabs.push({
            title: query,
            name: newTabName,
            content: [],
            total: 0,
            pageSize: 10,
            currentPage: 1,
            message: result.message + "," + result.data.rest_quota
        });
        table.acvtiveNames = newTabName
        const tab = table.editableTabs.find(tab => tab.name === newTabName)!;
        tab.content!.pop()
        if (result.data.arr == null) {
            ElMessage.warning("暂未查询到相关数据");
            table.loading = false
            return
        }
        result.data.arr!.forEach(item => {
            tab.content?.push({
                URL: item.url,
                IP: item.ip,
                Port: item.port,
                Protocol: item.protocol,
                Domain: item.domain,
                Component: item.component,
                Title: item.web_title,
                Status: item.status_code,
                ICP: item.company,
                ISP: item.isp,
                Position: item.country + "/" + item.province,
                UpdateTime: item.updated_at,
            })
        });
        tab.total = result.data.total
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
        table.loading = true
        let result = await HunterSearch(global.space.hunterapi, global.space.hunterkey, tab.title, val.toString(), "1", form.defaultTime, form.defaultSever, form.deduplication)
        if (isError(result.code, result.message)) {
            table.loading = false
            tab.message = result.message
            return
        }
        tab.message = result.message + "," + result.data.rest_quota
        tab.content = [{}]
        tab.content.pop()
        result.data.arr!.forEach(item => {
            tab.content?.push({
                URL: item.url,
                IP: item.ip,
                Port: item.port,
                Protocol: item.protocol,
                Domain: item.domain,
                Component: item.component,
                Title: item.web_title,
                Status: item.status_code,
                ICP: item.company,
                ISP: item.isp,
                Position: item.country + "/" + item.province,
                UpdateTime: item.updated_at,
            })
        });
        tab.total = result.data.total
        table.loading = false
    },
    handleCurrentChange: async (val: any) => {
        const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
        tab.currentPage = val
        table.loading = true
        let result = await HunterSearch(global.space.hunterapi, global.space.hunterkey, tab.title, tab.pageSize.toString(), val.toString(), form.defaultTime, form.defaultSever, form.deduplication)
        if (isError(result.code, result.message)) {
            table.loading = false
            tab.message = result.message
            return
        }
        tab.message = result.message + "," + result.data.rest_quota
        tab.content = [{}]
        tab.content.pop()
        result.data.arr!.forEach(item => {
            tab.content?.push({
                URL: item.url,
                IP: item.ip,
                Port: item.port,
                Protocol: item.protocol,
                Domain: item.domain,
                Component: item.component,
                Title: item.web_title,
                Status: item.status_code,
                ICP: item.company,
                ISP: item.isp,
                Position: item.country + "/" + item.province,
                UpdateTime: item.updated_at,
            })
        });
        tab.total = result.data.total
        table.loading = false
    },
    IconSearch: async function () {
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
                tableCtrl.addTab(`web.icon=="${hash}"`)
            }).catch(() => {
            })
    }
})

const excelHeaders = ["URL", "IP", "端口", "协议", "域名", "应用/组件", "标题", "状态码", "备案号", "运营商", "地理位置", "更新时间"]

async function exportData(mode: number) {
    if (table.editableTabs.length == 0) {
        ElNotification.warning({
            title: "Hunter Tips",
            message: "请先进行数据查询",
        })
        return
    }

    const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;
    if (tab.content.length === 0) {
        ElNotification.warning({
            title: "Hunter Tips",
            message: "当前查询条件并没有数据可导出",
        })
        return;
    }

    if (mode == 0 || tab.total <= tab.pageSize) {
        ExportToXlsx(excelHeaders, "asset", "hunter_asset", tab.content!);
        return
    }
    ElNotification.info({
        title: "Hunter Tips",
        message: "正在进行全数据导出, API每页最大查询限度100, 请稍后。",
    });

    let temp: any[] = [];
    let index = 0;

    for (const num of splitInt(tab.total, 100)) {
        index += 1;
        ElMessage(`正在查询第 ${index} 页`);

        let result = await HunterSearch(global.space.hunterapi, global.space.hunterkey, tab.title, "100", index.toString(), form.defaultTime, form.defaultSever, form.deduplication);

        if (isError(result.code, result.message)) {
            ElNotification.error({
                title: "Hunter Tips",
                message: `${tab.title} 导出数据时遇到错误: ${result.message}, 当前查询到第${index}页`,
            })
            break; // 遇到错误时停止后续查询
        }

        result.data.arr!.forEach(item => {
            temp.push({
                URL: item.url,
                IP: item.ip,
                Port: item.port,
                Protocol: item.protocol,
                Domain: item.domain,
                Component: item.component,
                Title: item.web_title,
                Status: item.status_code,
                ICP: item.company,
                ISP: item.isp,
                Position: `${item.country}/${item.province}`,
                UpdateTime: item.updated_at,
            });
        });
    }

    if (temp.length > 0) {
        ExportToXlsx(excelHeaders, "asset", "hunter_asset", temp);
        ElMessage.success(`已成功导出 ${temp.length} 条数据`);
    } else {
        ElMessage.warning("没有数据可导出");
    }
}

function isError(code: number, message: string) {
    if (code == 0) {
        ElMessage.warning("请求失败，请检查网络")
        return true
    }
    if (code == 40205) {
        ElNotification.info({
            title: "提示",
            message: message,
        });
        return true
    }
    if (code != 200) {
        ElNotification.info({
            title: "提示",
            message: message,
        });
        return false
    }
    return false
}

async function copyURLs(type: 'current' | 'top100', dedup: boolean = false) {
    if (table.editableTabs.length == 0) {
        ElNotification.warning({
            title: "Hunter Tips",
            message: "请先进行数据查询",
        });
        return;
    }

    const tab = table.editableTabs.find(tab => tab.name === table.acvtiveNames)!;

    let urls: string[] = [];

    if (type === 'current') {
        let data = tab.content!;
        if (dedup) {
            const seen = new Set();
            data = data.filter(item => {
                const key = `${item.ip}_${item.web_title}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }
        urls = data.map(item => item.URL);
    } else {
        const result = await HunterSearch(global.space.hunterapi, global.space.hunterkey, tab.title, "100", "1", form.defaultTime, form.defaultSever, form.deduplication)

        let data = result.data.arr;
        if (dedup) {
            const seen = new Set();
            data = data.filter(item => {
                const key = `${item.ip}_${item.web_title}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }

        urls = data.map(item => item.url);
    }

    Copy(urls.join("\n"));
}
function searchCsegmentIpv4(ip: string) {
    let ipv4 = CsegmentIpv4(ip)
    tableCtrl.addTab(`ip="${ipv4}"`)
}
</script>

<template>
    <el-form :model="form" @keydown.enter.native.prevent="tableCtrl.addTab(form.query)">
        <el-form-item>
            <el-autocomplete v-model="form.query" placeholder="Search..." :fetch-suggestions="entry.querySearchAsync"
                @select="entry.handleSelect" :debounce="500" class="w-full">
                <template #prepend>
                    查询条件
                </template>
                <template #suffix>
                    <el-space :size="2">
                        <el-popover placement="bottom-end" :width="700" trigger="click">
                            <template #reference>
                                <div>
                                    <el-tooltip content="常用关键词搜索" placement="bottom">
                                        <el-button :icon="CollectionTag" link />
                                    </el-tooltip>
                                </div>
                            </template>
                            <el-tabs v-model="form.keywordActive">
                                <el-tab-pane v-for="item in hunterOptions.Syntax" :name="item.title"
                                    :label="item.title">
                                    <el-table :data="item.data" class="keyword-search" @row-click="entry.rowClick"
                                        style="height: 50vh;">
                                        <el-table-column width="300" property="key" label="例句">
                                            <template #default="scope">
                                                <el-space>
                                                    <span>{{ scope.row.key }}</span>
                                                    <el-tag type="danger" round v-show="scope.row.hot">hot</el-tag>
                                                    <el-tag type="primary" round
                                                        v-show="scope.row.characteristic">特色</el-tag>
                                                </el-space>
                                            </template>
                                        </el-table-column>
                                        <el-table-column property="description" label="用途说明" />
                                    </el-table>
                                </el-tab-pane>
                            </el-tabs>
                        </el-popover>
                        <el-tooltip content="使用网页图标搜索" placement="bottom">
                            <el-button :icon="PictureRounded" link @click="tableCtrl.IconSearch" />
                        </el-tooltip>
                    </el-space>
                    <el-divider direction="vertical" />
                    <el-space :size="2">
                        <el-tooltip content="清空语法" placement="bottom">
                            <el-button :icon="Delete" link @click="form.query = ''" />
                        </el-tooltip>
                        <el-tooltip content="收藏语法" placement="bottom">
                            <el-button :icon="Star" link @click="syntax.createStarDialog" />
                        </el-tooltip>
                        <el-tooltip content="复制语法" placement="bottom">
                            <el-button :icon="DocumentCopy" link @click="Copy(form.query)" />
                        </el-tooltip>
                        <el-divider direction="vertical" />
                    </el-space>
                    <el-button link :icon="Search" @click="tableCtrl.addTab(form.query)"
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
                            <el-table :data="form.syntaxData" @row-click="entry.rowClick2" class="keyword-search">
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
                    <el-space>
                        <span>{{ item.value }}</span>
                        <el-divider direction="vertical" />
                        <span>数量: {{ item.assetNum }}</span>
                        <el-divider direction="vertical" />
                        <el-tag v-for="label in item.tags">{{ label }}</el-tag>
                    </el-space>
                </template>
            </el-autocomplete>
        </el-form-item>
        <el-form-item>
            <el-space>
                <el-select v-model="form.defaultTime" style="width: 200px;">
                    <el-option v-for="item in hunterOptions.Time" :key="item.value" :label="item.label"
                        :value="item.value">
                        <span class="float-left">{{ item.label }}</span>
                        <span class="float-right">
                            {{ item.tips }}
                        </span>
                    </el-option>
                </el-select>
                <el-select v-model="form.defaultSever" style="width: 200px;">
                    <el-option v-for="item in hunterOptions.Server" :key="item.value" :label="item.label"
                        :value="item.value" style="text-align: center;" />
                </el-select>
                <el-tooltip content="需要权益积分">
                    <el-checkbox v-model="form.deduplication">数据去重</el-checkbox>
                </el-tooltip>
            </el-space>
            <div style="flex-grow: 1;"></div>
            <el-dropdown>
                <el-button type="primary" text bg>
                    更多功能<el-icon class="el-icon--right">
                        <ArrowDown />
                    </el-icon>
                </el-button>
                <template #dropdown>
                    <el-dropdown-menu>
                        <el-dropdown-item :icon="Share" @click="exportData(0)">导出当前查询页数据</el-dropdown-item>
                        <el-dropdown-item :icon="Share" @click="exportData(1)">导出全部数据</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('current', false)" divided>复制当前页URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('top100', false)">复制前100条URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('current', true)" divided>去重复制当前页URL</el-dropdown-item>
                        <el-dropdown-item :icon="DocumentCopy" @click="copyURLs('top100', true)">去重复制前100条URL</el-dropdown-item>
                    </el-dropdown-menu>
                </template>
            </el-dropdown>
        </el-form-item>
    </el-form>
    <el-tabs class="editor-tabs mt-10px" v-model="table.acvtiveNames" v-loading="table.loading" type="card"
         closable @tab-remove="tableCtrl.removeTab">
        <el-tab-pane v-for="item in table.editableTabs" :key="item.name" :label="item.title" :name="item.name"
            v-if="table.editableTabs.length != 0">
            <el-table :data="item.content" border class="w-full" style="height: calc(100vh - 275px);">
                <el-table-column type="index" fixed label="#" width="60px" />
                <el-table-column prop="URL" fixed label="URL" :min-width="200" :show-overflow-tooltip="true" />
                <el-table-column prop="IP" fixed label="IP" width="150" :show-overflow-tooltip="true" />
                <el-table-column prop="Port" fixed label="端口/服务" width="150">
                    <template #default="scope">
                        <el-space :size="3">
                            <span>{{ scope.row.Port }}</span>
                            <el-tag type=info round>{{ scope.row.Protocol }}</el-tag>
                        </el-space>
                    </template>
                </el-table-column>
                <el-table-column prop="Domain" label="域名" width="150" :show-overflow-tooltip="true" />
                <el-table-column prop="Component" label="应用/组件" width="210xp">
                    <template #default="scope">
                        <el-space>
                            <el-tag round v-if="Array.isArray(scope.row.Component) && scope.row.Component.length > 0">{{
                                scope.row.Component[0].name + scope.row.Component[0].version }}</el-tag>
                            <el-popover placement="bottom" :width="350" trigger="hover">
                                <template #reference>
                                    <el-button round size="small"
                                        v-if="Array.isArray(scope.row.Component) && scope.row.Component.length > 0">共{{
                                            scope.row.Component.length }}条</el-button>
                                </template>
                                <template #default>
                                    <el-space direction="vertical">
                                        <el-tag round v-for="component in scope.row.Component" style="width: 320px;">{{
                                            component.name +
                                            component.version }}</el-tag>
                                    </el-space>
                                </template>
                            </el-popover>
                        </el-space>
                    </template>
                </el-table-column>
                <el-table-column prop="Title" label="标题" width="150" :show-overflow-tooltip="true" />
                <el-table-column prop="Status" label="状态码" width="100" :show-overflow-tooltip="true" />
                <el-table-column prop="ICP" label="备案名称" width="150" :show-overflow-tooltip="true" />
                <el-table-column prop="ISP" label="运营商" width="150" :show-overflow-tooltip="true" />
                <el-table-column prop="Position" label="地理位置" width="120" :show-overflow-tooltip="true" />
                <el-table-column prop="UpdateTime" label="更新时间" width="150" :show-overflow-tooltip="true" />
                <el-table-column fixed="right" label="操作" width="100" align="center">
                    <template #default="scope">
                        <el-tooltip content="打开链接" placement="top">
                            <el-button link :icon="ChromeFilled" @click.prevent="openURL(scope.row.URL)" />
                        </el-tooltip>
                        <el-divider direction="vertical" />
                        <el-tooltip content="C段查询" placement="top">
                            <el-button link :icon="csegmentIcon" @click.prevent="searchCsegmentIpv4(scope.row.IP)">
                            </el-button>
                        </el-tooltip>
                    </template>
                </el-table-column>
            </el-table>
            <div class="flex-between mt-10px">
                <span style="color: cornflowerblue;">{{ item.message }}</span>
                <el-pagination size="small" background v-model:page-size="item.pageSize" :page-sizes="[10, 50, 100]"
                    layout="total, sizes, prev, pager, next, jumper" @size-change="tableCtrl.handleSizeChange"
                    @current-change="tableCtrl.handleCurrentChange" :total="item.total" />
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
                <el-button type="primary" @click="syntax.submitStar(ruleFormRef)">
                    确定
                </el-button>
                <el-button @click="syntax.starDialog.value = false">取消</el-button>
            </el-form-item>
        </el-form>
    </el-dialog>
</template>

<style scoped></style>