import os
import re

# 配置需要扫描的文件夹路径，'.' 表示当前目录及其子目录
# 如果你想只修 posts，可以改成 './src/content/posts'
TARGET_DIR = '.'

# 正则解释：
# (!?\[.*?\])  捕获组1: 匹配 ![desc] 或 [link]
# \(           匹配左括号
# ([^)]+)      捕获组2: 匹配括号内的内容（即路径），直到遇到右括号
# \)           匹配右括号
LINK_PATTERN = re.compile(r'(!?\[.*?\])\(([^)]+)\)')


def fix_content(content):
    def replace_callback(match):
        prefix = match.group(1)
        path = match.group(2)

        # 只有当路径里包含反斜杠时才替换
        if '\\' in path:
            # 将反斜杠替换为正斜杠
            new_path = path.replace('\\', '/')
            print(f"  [Fixing]: {path} -> {new_path}")
            return f'{prefix}({new_path})'

        return match.group(0)

    # 使用 sub 进行替换
    return LINK_PATTERN.sub(replace_callback, content)


def main():
    count = 0
    print(f"Starting scan in: {os.path.abspath(TARGET_DIR)}")

    for root, dirs, files in os.walk(TARGET_DIR):
        # 忽略 .git 和 node_modules 目录，提高效率
        if '.git' in dirs: dirs.remove('.git')
        if 'node_modules' in dirs: dirs.remove('node_modules')

        for file in files:
            if file.endswith('.md') or file.endswith('.mdx'):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 检查并修复内容
                    new_content = fix_content(content)

                    # 如果内容有变化，则写回文件
                    if content != new_content:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"✅ Saved: {file_path}")
                        count += 1

                except Exception as e:
                    print(f"❌ Error processing {file_path}: {e}")

    if count == 0:
        print("\n✨ 没有发现需要修复的路径。")
    else:
        print(f"\n🚀 完成！共修复了 {count} 个文件。")


if __name__ == '__main__':
    main()