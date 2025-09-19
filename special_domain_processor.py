#!/usr/bin/env python3
"""
特殊域名分类脚本
"""

import subprocess
import os

def run_special_domain_classification():
    """
    运行特殊域名分类
    """
    # 确保输出目录存在
    special_output_dir = "domain-check/special"
    if not os.path.exists(special_output_dir):
        os.makedirs(special_output_dir)
    
    # 运行域名分类器处理特殊域名文件
    cmd = [
        "python3", "domain_classifier.py",
        "--input", "domain-scan-results-combined/special_status_domains_all.txt",
        "--output", special_output_dir
    ]
    
    print("正在处理特殊域名文件...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("特殊域名分类完成!")
        print(result.stdout)
    else:
        print("处理特殊域名时出错:")
        print(result.stderr)

if __name__ == "__main__":
    run_special_domain_classification()