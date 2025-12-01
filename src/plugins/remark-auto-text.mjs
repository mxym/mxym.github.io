import { visit } from 'unist-util-visit';

// 这里设置阈值：超过 300 行的代码块，自动变纯文本
const MAX_LINES = 300;

export function remarkAutoText() {
  return (tree) => {
    visit(tree, 'code', (node) => {
      // 1. 如果代码块本身就没有指定语言，或者已经是 text，就跳过
      if (!node.lang || node.lang === 'text') return;

      // 2. 计算行数
      const lineCount = node.value.split('\n').length;

      // 3. 如果行数超标，强制修改语言为 text
      if (lineCount > MAX_LINES) {
        console.warn(`[性能优化] 检测到超长代码块 (${lineCount} 行)，已自动降级为纯文本模式。`);
        node.lang = 'text';
        // node.meta = ''; // 可选：清空其他属性
      }
    });
  };
}