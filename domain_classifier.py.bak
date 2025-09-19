import os
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
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
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

if __name__ == "__main__":
    input_file = "domain-scan-results-combined/available_domains_all.txt"
    output_dir = "domain-check"
    
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 {input_file} 不存在")
        exit(1)
    
    classify_domains(input_file, output_dir)
    print(f"域名分类完成，结果保存在 {output_dir} 目录中")