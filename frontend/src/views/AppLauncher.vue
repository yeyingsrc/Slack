<script lang="ts" setup>
import { ElMessage, ElMessageBox, ElNotification } from "element-plus";
import { reactive, ref, h, computed } from "vue";
import { DeleteFilled, Edit, FolderOpened, Document, Menu, WarningFilled, Guide, PictureRounded, DocumentCopy } from "@element-plus/icons-vue";
import { onMounted } from "vue";
import { OnFileDrop } from "wailsjs/runtime/runtime";
import { Path, GetLocalNaConfig, InsetGroupNavigation, InsetItemNavigation, OpenFolder, SaveNavigation, RunApp, FileDialog, OpenTerminal, GenerateFaviconBase64WithOnline, GenerateFaviconBase64, AutoGenerateFavicon, SnippetCommandLine } from "wailsjs/go/services/File";
import ContextMenu from '@imengyu/vue3-context-menu'
import groupIcon from "@/assets/icon/tag-group.svg"
import tagIcon from "@/assets/icon/tag.svg"
import { appStartStyle, defaultIconSize } from "@/stores/style";
import consoleIcon from '@/assets/icon/console.svg'
import appIcon from '@/assets/icon/app.svg'
import javaIcon from '@/assets/icon/java.svg'
import itermIcon from '@/assets/icon/iterm.svg'
import chromeIcon from '@/assets/icon/chrome.svg'
import buttonIcon from '@/assets/icon/button.svg'
import gridIcon from '@/assets/icon/grid.svg'
import scriptIcon from '@/assets/icon/script.svg'
import global from "@/stores";
import { structs } from "wailsjs/go/models";
import Note from "@/components/Note.vue";
import { Copy } from "@/util";


onMounted(async () => {
    OnFileDrop((x, y, paths) => {
        const el = document.elementFromPoint(x, y);
        if (!el) return;

        const target = el.closest('[data-group]');
        if (!target) return;

        const groupName = target.getAttribute('data-group');
        if (!groupName) return;

        const card = localGroup.options.value.find(item => item.Name === groupName);
        if (!card) return;

        paths.forEach(async (p) => {
            if (!p) return;
            const pathinfo = await Path(p);
            const base64Icon = await AutoGenerateFavicon(p);
            const c = {
                Name: pathinfo.Name,
                Type: localGroup.getExtType(pathinfo.Ext),
                Path: p,
                Target: "",
                Favicon: base64Icon,
                Args: "",
            };
            card.Children = card.Children || [];
            card.Children.push(c);
            InsetItemNavigation(groupName, c);
        });
    }, true);
    let groups = await GetLocalNaConfig()
    if (groups) {
        localGroup.options.value = groups
    } else {
        ElMessageBox.alert('可以通过右上角|右键添加分组，然后分组右键添加启动应用', 'Tips', {})
    }
})

var edit = reactive({
    Name: "",
    Path: "",
    Type: "",
    Target: "",
    Favicon: "",
    Args: "",
})

const config = reactive({
    defaultType: "CMD",
    defualtGroupName: "",
    name: "",
    path: "",
    target: "",
    favicon: "",
    args: "",
    editDialog: false,
    editChild: {} as structs.Children, // 存储被修改元素之前的状态，为了后续在配置文件中找到是哪个元素被修改了
    editGroupName: "", // 正在被编辑的组名
    addItemDialog: false,
    tipsDialog: false,
})

const searchFilter = ref("")

const filteredGroups = computed(() => {
    if (!searchFilter.value) return localGroup.options.value; // 如果没有搜索关键词，返回所有组
    return localGroup.options.value.map(group => {
        // 检查组内是否有元素包含搜索关键词
        const filteredChildren = group.Children?.filter(item => item.Name.toLowerCase().includes(searchFilter.value.toLowerCase())) || [];
        if (filteredChildren.length === 0) return null; // 如果过滤后没有元素，则不返回该组
        return {
            ...group,
            Children: filteredChildren,
        };
    }).filter(group => group !== null); // 过滤掉返回为null的组
});

const localGroup = ({
    options: ref<structs.Navigation[]>([]),
    openGroup: [
        {
            name: "CMD",
            icon: itermIcon,
        },
        {
            name: "APP",
            icon: appIcon,
        },
        {
            name: "JAR",
            icon: javaIcon,
        },
        {
            name: "Link",
            icon: chromeIcon,
        },
        // {
        //     name: "Script",
        //     icon: scriptIcon,
        // }
    ],
    getGroupsName: function () {
        return localGroup.options.value.map(item => item.Name) // 获取所有分组名称
    },
    showDefaultFavicon: function (type: string) {
        switch (type) {
            case "JAR":
                return javaIcon
            case "APP":
                return appIcon
            case "Link":
                return chromeIcon
            case "Script":
                return scriptIcon
            default:
                return itermIcon
        }
    },
    getExtType: function (type: string) {
        if (type == "JAR") {
            return type
        } else if (type == "LNK" || type == "EXE" || type == "BAT") {
            return "APP"
        }
        return "CMD"
    },
    addGroup: function () {
        ElMessageBox.prompt('请输入名称(不能重名)', "添加分组", {
            inputPattern: /.+/,
            inputErrorMessage: "Group name can't be empty",
        })
            .then(({ value }) => {
                let existingGroup = localGroup.options.value.find(item => item.Name == value)?.Name
                if (existingGroup) {
                    ElMessage.warning("A group name with the same name already exists, please rename it")
                    return
                } else {
                    localGroup.options.value.push({
                        Name: value,
                        Children: [],
                        convertValues: () => { },
                    })
                    InsetGroupNavigation({
                        Name: value,
                        Children: [],
                        convertValues: () => { },
                    })
                }
            })
    },
    addItem: async function () {
        let card = localGroup.options.value.find(item => item.Name === config.defualtGroupName)
        if (card) {
            if (config.defaultType == "Link" && config.path.startsWith("http")) {
                ElMessage("正在加载图标资源，加载完毕后会自动关闭窗口...")
                config.favicon = await GenerateFaviconBase64WithOnline(config.path)
            } else {
                config.favicon = await AutoGenerateFavicon(config.path)
            }
            let child = {
                Name: config.name,
                Type: config.defaultType,
                Path: config.path,
                Target: config.target,
                Favicon: config.favicon,
                Args: config.args
            }
            if (!card.Children) {
                card.Children = [child];
            } else {
                card.Children.push(child)
            }
            InsetItemNavigation(config.defualtGroupName, child)
        }
        config.addItemDialog = false
    },
    deleteGroup: function (name: string) {
        ElMessageBox.confirm(
            '确定删除该分组?',
            '警告',
            {
                type: 'warning',
            }
        )
            .then(() => {
                localGroup.options.value = localGroup.options.value.filter(item => item.Name !== name)
                SaveNavigation(localGroup.options.value)
            })
            .catch(() => {

            })
    },
    deleteItem: function (groupName: string, child: structs.Children) {
        localGroup.options.value = localGroup.options.value.map(group => {
            if (group.Name === groupName) {
                return {
                    ...group,
                    Children: group.Children?.filter(c => c.Name !== child.Name || c.Type !== child.Type || c.Path !== child.Path) || null
                };
            }
            return group;
        });
        SaveNavigation(localGroup.options.value)
    },
    saveEdit: function () {
        const groupIndex = localGroup.options.value.findIndex(group =>
            group.Name == config.editGroupName
        );
        if (groupIndex !== -1) { // If the group is found
            localGroup.options.value[groupIndex].Children!.forEach((item, index) => {
                if (item == config.editChild) {
                    localGroup.options.value[groupIndex].Children![index] = edit
                    SaveNavigation(localGroup.options.value);
                    config.editDialog = false;
                }
            });
        }
    },
    moveItem: function (fromGroupName: string, toGroupName: string, child: structs.Children) {
        const fromGroupIndex = localGroup.options.value.findIndex(group =>
            group.Name == fromGroupName
        );
        const toGroupIndex = localGroup.options.value.findIndex(group =>
            group.Name == toGroupName
        );
        if (fromGroupIndex !== -1 && toGroupIndex !== -1) {
            const itemToMoveIndex = localGroup.options.value[fromGroupIndex].Children!.findIndex(item =>
                item.Name == child.Name && item.Type == child.Type && item.Path == child.Path
            );
            if (itemToMoveIndex !== -1) {
                const [itemToMove] = localGroup.options.value[fromGroupIndex].Children!.splice(itemToMoveIndex, 1);
                localGroup.options.value[toGroupIndex].Children!.push(itemToMove);
                SaveNavigation(localGroup.options.value);
            }
        }
    },
    handleOpenFolder: async function (filepath: string) {
        let error = await OpenFolder(filepath)
        if (error != "") {
            ElMessage.error(error)
        }
    },
    selectPathFile: async function () {
        config.path = await FileDialog("")
    },
    selctFaviconFile: async function () {
        let filepath = await FileDialog("*.ico;*.png;*.jpg;*.jpeg;*.svg")
        config.favicon = await GenerateFaviconBase64(filepath)
    },
    editFaviconFile: async function () {
        let filepath = await FileDialog("*.ico;*.png;*.jpg;*.jpeg;*.svg")
        edit.Favicon = await GenerateFaviconBase64(filepath)
    },
    editPathFile: async function () {
        edit.Path = await FileDialog("")
    },
})

function handleCardContextMenu(e: MouseEvent, groups: any) {
    //prevent the browser's default menu
    e.preventDefault();
    //show our menu
    ContextMenu.showContextMenu({
        x: e.x,
        y: e.y,
        items: [
            {
                label: "添加元素",
                icon: h(tagIcon, defaultIconSize),
                onClick: () => {
                    config.addItemDialog = true
                    config.name = ""
                    config.target = ""
                    config.path = ""
                    config.favicon = ""
                    config.defualtGroupName = groups.Name
                }
            },
            {
                label: "添加分组",
                icon: h(groupIcon, defaultIconSize),
                divided: true,
                onClick: () => {
                    localGroup.addGroup()
                }
            },
            {
                label: "删除分组",
                icon: h(DeleteFilled, defaultIconSize),
                divided: true,
                onClick: () => {
                    localGroup.deleteGroup(groups.Name)
                }
            },
            {
                label: "视图模式",
                icon: h(Menu, defaultIconSize),
                children: [
                    {
                        label: "图标模式",
                        icon: h(gridIcon, defaultIconSize),
                        onClick: () => {
                            global.temp.isGrid = true
                        }
                    },
                    {
                        label: "按钮模式",
                        icon: h(buttonIcon, defaultIconSize),
                        onClick: () => {
                            global.temp.isGrid = false
                        }
                    },
                ]
            },
        ]
    });
}

function handleButtonContextMenu(e: MouseEvent, groups: any, item: any) {
    e.preventDefault();
    ContextMenu.showContextMenu({
        x: e.x,
        y: e.y,
        items: [
            {
                label: "打开文件夹",
                icon: h(FolderOpened, defaultIconSize),
                onClick: () => {
                    localGroup.handleOpenFolder(item.Path)
                }
            },
            {
                label: "打开文件所在命令行",
                icon: h(consoleIcon, defaultIconSize),
                onClick: () => {
                    OpenTerminal(item.Path)
                }
            },
            {
                label: "复制占位符命令",
                icon: h(DocumentCopy, defaultIconSize),
                onClick: () => {
                    if (item.Type != "Script") {
                        ElNotification({
                            title: "错误",
                            message: "仅Script类型应用支持复制",
                            type: "error",
                            position: 'bottom-right',
                        })
                        return
                    }
                    SnippetCommandLine(item).then(command => {
                        Copy(command)
                    })
                }
            },
            {
                label: "移动至",
                icon: h(Guide, defaultIconSize),
                children: localGroup.getGroupsName().map(name => ({
                    label: name,
                    onClick: () => {
                        localGroup.moveItem(groups.Name, name, item);
                    }
                }))
            },
            {
                label: "编辑",
                icon: h(Edit, defaultIconSize),
                onClick: () => {
                    config.editDialog = true;
                    Object.assign(edit, item);
                    config.editChild = item;
                    config.editGroupName = groups.Name;
                }
            },
            {
                label: "删除",
                icon: h(DeleteFilled, defaultIconSize),
                onClick: () => {
                    localGroup.deleteItem(groups.Name, item)
                }
            },
        ]
    });
}
</script>


<template>
    <div class="flex-between mb-10px">
        <el-button plain :icon="WarningFilled" @click="config.tipsDialog = true">使用须知</el-button>
        <el-input v-model="searchFilter" placeholder="根据名称过滤搜索..." style="margin-inline: 5px">
            <template #prefix>
                <el-icon>
                    <Filter />
                </el-icon>
            </template>
        </el-input>
        <el-button :icon="groupIcon" @click="localGroup.addGroup()">添加分组</el-button>
    </div>
    <div v-if="filteredGroups.length > 0" v-for="groups in filteredGroups" class="mb-5px">
        <el-card @drop="(event: DragEvent) => event.preventDefault()" class="drop-enable"
            @contextmenu.stop.prevent="handleCardContextMenu($event, groups)" :data-group="groups.Name">
            <div class="flex-between" style="margin-bottom: 20px">
                <span class="font-bold">{{ groups.Name }}</span>
                <el-button :icon="DeleteFilled" link @click="localGroup.deleteGroup(groups.Name)"></el-button>
            </div>
            <div v-if="groups.Children" :style="appStartStyle">
                <div v-for="(item, index) in groups.Children" :key="index">
                    <el-tooltip :content="item.Name" :show-after="500">
                        <div class="card-content" v-show="global.temp.isGrid" @click="RunApp(item)"
                            @contextmenu.stop.prevent="handleButtonContextMenu($event, groups, item)">
                            <component v-if="item.Favicon == ''" :is="localGroup.showDefaultFavicon(item.Type)"
                                style="width: 40px; height: 40px;">
                            </component>
                            <img v-else :src="item.Favicon" style="width: 40px; height: 40px;">
                            <span class="fixed-length-span">{{ item.Name }}</span>
                        </div>
                    </el-tooltip>
                    <div v-show="!global.temp.isGrid">
                        <el-button bg text @click="RunApp(item)"
                            @contextmenu.stop.prevent="handleButtonContextMenu($event, groups, item)">
                            <template #icon>
                                <el-icon v-if="item.Favicon == ''">
                                    <component :is="localGroup.showDefaultFavicon(item.Type)"></component>
                                </el-icon>
                                <img v-else :src="item.Favicon" style="width: 16px; height: 16px;">
                            </template>
                            {{ item.Name }}
                        </el-button>
                    </div>
                </div>
            </div>
        </el-card>
    </div>
    <el-empty v-else></el-empty>
    <el-dialog v-model="config.addItemDialog" :title="$t('navigator.add_item')" width="550">
        <el-form :model="config" label-width="auto">
            <el-form-item label="组名">
                <el-select v-model="config.defualtGroupName">
                    <el-option v-for="name in localGroup.getGroupsName()" :value="name">{{ name }}</el-option>
                </el-select>
            </el-form-item>
            <el-form-item label="名称">
                <el-input v-model="config.name" />
            </el-form-item>
            <el-form-item label="类型">
                <el-radio-group v-model="config.defaultType" text-color="#626aef" fill="rgb(239, 240, 253)">
                    <el-radio-button v-for="item in localGroup.openGroup" :key="item.name" :value="item.name">
                        <el-space :size="6">
                            <el-icon :size="18">
                                <component :is="item.icon" />
                            </el-icon>
                            <span class="font-bold">{{ item.name }}</span>
                        </el-space>
                    </el-radio-button>
                </el-radio-group>
            </el-form-item>
            <el-form-item label="命令" v-show="config.defaultType == 'CMD' || config.defaultType == 'Script'">
                <el-input v-model="config.target" type="textarea" :rows="5" />
            </el-form-item>
            <el-form-item label="占位参数" v-show="config.defaultType == 'Script'">
                <el-input v-model="config.args" type="textarea" :rows="5" />
                <span class="form-item-tips">仅当类型为Script时, 替换命令中的占位符使用</span>
            </el-form-item>
            <el-form-item label="文件路径">
                <el-input v-model="config.path">
                    <template #suffix>
                        <el-button :icon="Document" link @click="localGroup.selectPathFile" />
                    </template>
                </el-input>
                <span class="form-item-tips">类型为Link时路径填写URL网址</span>
            </el-form-item>
            <el-form-item label="图标">
                <el-input v-model="config.favicon">
                    <template #suffix>
                        <el-button :icon="PictureRounded" link @click="localGroup.selctFaviconFile" />
                    </template>
                </el-input>
                <span class="form-item-tips">Link类型、App中的EXE、LNK应用可以自动获取图标</span>
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button type="primary" @click="localGroup.addItem">
                保存
            </el-button>
        </template>
    </el-dialog>
    <el-dialog v-model="config.editDialog" :title="$t('navigator.edit_item')" width="550">
        <el-form :model="edit" label-width="auto">
            <el-form-item label="名称">
                <el-input v-model="edit.Name" />
            </el-form-item>
            <el-form-item label="类型">
                <el-radio-group v-model="edit.Type" text-color="#626aef" fill="rgb(239, 240, 253)">
                    <el-radio-button v-for="item in localGroup.openGroup" :key="item.name" :value="item.name">
                        <el-space :size="6">
                            <el-icon :size="18">
                                <component :is="item.icon" />
                            </el-icon>
                            <span class="font-bold">{{ item.name }}</span>
                        </el-space>
                    </el-radio-button>
                </el-radio-group>
            </el-form-item>
            <el-form-item label="命令" v-show="edit.Type == 'CMD' || edit.Type == 'Script'">
                <el-input v-model="edit.Target" type="textarea" :rows="5" />
            </el-form-item>
            <el-form-item label="占位参数" v-show="edit.Type == 'Script'">
                <el-input v-model="edit.Args" type="textarea" :rows="5" />
                <span class="form-item-tips">仅当类型为Script时, 替换命令中的占位符使用</span>
            </el-form-item>
            <el-form-item label="文件路径">
                <el-input v-model="edit.Path">
                    <template #suffix>
                        <el-button :icon="Document" link @click="localGroup.editPathFile" />
                    </template>
                </el-input>
                <span class="form-item-tips">类型为Link时路径填写URL网址</span>
            </el-form-item>
            <el-form-item label="图标">
                <el-input v-model="edit.Favicon">
                    <template #suffix>
                        <el-button :icon="PictureRounded" link @click="localGroup.editFaviconFile" />
                    </template>
                </el-input>
                <span class="form-item-tips">Link类型、App中的EXE、LNK应用可以自动获取图标</span>
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button type="primary" @click="localGroup.saveEdit">
                保存
            </el-button>
        </template>
    </el-dialog>
    <el-dialog v-model="config.tipsDialog" width="900px">
        <Note>
            1、jar应用在默认点击启动时, 会使用以java -jar启动应用<br />
            如果在启动jar GUI应用时出现无法打开的情况，可能是使用了切换Java环境变量的一些功能应用，需要配置实际Java bin的路径
            <br /><br />
            2、如果默认配置无法满足使用, 可以通过填写目标自定义启动命令<strong>(类型必须为CMD)</strong>, %path%关键词可以自动替换为应用路径<br />
            e.g. 启动Exp-Tools, 路径为: <code>/Users/xxx/exp/Exp-Tools-1.2.7-encrypted.jar</code> 命令可以为:
            <code>java -javaagent:%path% -jar %path%</code><br /><br />
            3、拖入应用到分组中会自动按类型添加元素<br /><br />
            4、每个面板右键都有独立的功能!!!<br /><br />
            5、Link类型可以在路径处填写网址链接, 作为书签使用<br /><br />
            6、应用默认添加时Link类型以及EXE、LNK应用会自动获取图标信息(图标参数为空会使用默认图标, 部分应用可能无法正常显示需要自行设置), 对于20kb以上图标会进行压缩存储<br /><br />
            7、Script类型表示需要程序打开终端, 将预输入好的命令输入到命令行中, 支持参数化编写<br />
            e.g. 我需要执行jwt-crack, 则命令为:
            <code>jwt-hack crack %token% -w %dict%
            参数为(根据;号分割):
            %token%:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOiIxIiwicm5TdHIiOiJUc1RwSFBNUlZaeGtKZWREUGFxa281ZVdTUlBSZmQ4bCJ9.QsplJJwqcW5rmRoEbA2h0VtsAzvfX5E-SkxOjqRhKy4;%dict%:/Users/xxx/jwt.txt</code>
        </Note>
    </el-dialog>
</template>


<style scoped>
.card-content {
    display: flex;
    /* 内容容器为 flex 容器 */
    flex-direction: column;
    /* 子元素竖直排列 */
    align-items: center;
    /* 垂直居中 */
    padding: 5px;
}

.card-content:hover {
    background-color: var(--list-item-hover-color);
    cursor: pointer;
    padding: 5px;
}

.icon {
    width: 40px;
    height: 40px;
}

.fixed-length-span {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    display: inline-block;
    text-align: center;
    max-width: 80px;
    font-size: 12px;
    margin-top: 10px;
}

.drop-enable {
    --wails-drop-target: drop;
}
</style>