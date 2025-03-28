// 简单的右键菜单事件在此管理

import { defaultIconSize } from "@/stores/style";
import ContextMenu from '@imengyu/vue3-context-menu'
import { h } from "vue";
import { Copy } from "@/util";
import { BrowserOpenURL } from "wailsjs/runtime/runtime";
import { DocumentCopy, ChromeFilled, Promotion} from '@element-plus/icons-vue';
import router from "@/router";

export function handleWebscanContextMenu(row: any, column: any, e: MouseEvent) {
    //prevent the browser's default menu
    e.preventDefault();
    //show our menu
    ContextMenu.showContextMenu({
        x: e.x,
        y: e.y,
        items: [
            {
                label: "复制链接",
                icon: h(DocumentCopy, defaultIconSize),
                onClick: () => {
                    Copy(row.URL)
                }
            },
            {
                label: "打开链接",
                icon: h(ChromeFilled, defaultIconSize),
                onClick: () => {
                    BrowserOpenURL(row.URL)
                }
            },
            {
                label: "复制并跳转到目录扫描",
                icon: h(Promotion, defaultIconSize),
                onClick: () => {
                    Copy(row.URL)
                    router.push('/Permeation/Dirsearch')
                }
            },
        ]
    });
}