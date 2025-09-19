import os
import argparse
from collections import defaultdict

def get_domain_pattern(domain):
    """
    分析域名的字符模式
    例如: aaaa, aaab, abab 等
    """
    # 移除可能的点和顶级域名，只保留主域名部分
    if '.' in domain:
        main_domain = domain.split('.')[0].lower()
    else:
        main_domain = domain.lower()
    
    # 创建字符到字母的映射
    char_map = {}
    pattern_chars = []
    next_char = 'A'
    
    for char in main_domain:
        if char not in char_map:
            char_map[char] = next_char
            next_char = chr(ord(next_char) + 1)
        pattern_chars.append(char_map[char])
    
    return ''.join(pattern_chars)

def load_domains_from_file(file_path):
    """
    从文件加载域名，处理两种格式：
    1. 纯域名列表（每行一个域名）
    2. 特殊状态域名（格式：domain status reason）
    """
    domains = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # 跳过注释行和空行
            if not line or line.startswith('#'):
                continue
            
            # 如果是特殊状态文件格式（包含空格），只取域名部分
            if ' ' in line:
                domain = line.split()[0]
            else:
                domain = line
            
            domains.append(domain)
    
    return domains

def classify_domains(input_file, output_dir):
    """
    将域名按模式分类并保存到不同的文件中
    """
    # 创建输出目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 使用字典存储每个模式的域名
    pattern_domains = defaultdict(list)
    
    # 读取域名文件
    domains = load_domains_from_file(input_file)
    
    # 分类域名
    for domain in domains:
        pattern = get_domain_pattern(domain)
        pattern_domains[pattern].append(domain)
    
    # 为每个模式创建文件（仅当存在该模式的域名时）
    for pattern, domain_list in pattern_domains.items():
        output_file = os.path.join(output_dir, f"{pattern}.txt")
        with open(output_file, 'w') as f:
            for domain in sorted(domain_list):
                f.write(f"{domain}\n")
    
    # 打印统计信息
    print(f"总共处理了 {len(domains)} 个域名")
    print(f"发现了 {len(pattern_domains)} 种不同的模式:")
    for pattern in sorted(pattern_domains.keys()):
        print(f"  {pattern}: {len(pattern_domains[pattern])} 个域名")

def main():
    parser = argparse.ArgumentParser(description='将域名按字符模式分类')
    parser.add_argument('--input', '-i', required=True, help='输入域名文件路径')
    parser.add_argument('--output', '-o', required=True, help='输出目录路径')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"错误: 输入文件 {args.input} 不存在")
        exit(1)
    
    classify_domains(args.input, args.output)
    print(f"域名分类完成，结果保存在 {args.output} 目录中")

if __name__ == "__main__":
    main()