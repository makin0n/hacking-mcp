#!/usr/bin/env python3
"""
nmapテスト用スクリプト
Docker環境でのnmap動作確認
"""

import subprocess
import sys

def test_nmap_commands():
    """nmapコマンドのテスト"""
    
    test_commands = [
        # 基本テスト
        ["sudo", "nmap", "--version"],
        
        # 自分自身への基本スキャン（ループバック以外）
        ["sudo", "nmap", "-sS", "-p", "80,443", "8.8.8.8"],
        
        # TCPコネクトスキャン（非root権限でも動作）
        ["nmap", "-sT", "-p", "80,443", "8.8.8.8"],
        
        # サービス検出
        ["sudo", "nmap", "-sV", "--top-ports", "10", "8.8.8.8"],
        
        # UDPスキャン
        ["sudo", "nmap", "-sU", "--top-ports", "5", "8.8.8.8"],
    ]
    
    for i, cmd in enumerate(test_commands, 1):
        print(f"\n=== テスト {i}: {' '.join(cmd)} ===")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            print(f"戻り値: {result.returncode}")
            if result.stdout:
                print("STDOUT:")
                print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
            if result.stderr:
                print("STDERR:")
                print(result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr)
                
        except subprocess.TimeoutExpired:
            print("タイムアウト")
        except Exception as e:
            print(f"エラー: {e}")
        
        print("-" * 50)

def test_sudo_permissions():
    """sudo権限のテスト"""
    print("=== sudo権限テスト ===")
    
    try:
        result = subprocess.run(
            ["sudo", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        print("sudo権限:")
        print(result.stdout)
        
    except Exception as e:
        print(f"sudo権限確認エラー: {e}")

if __name__ == "__main__":
    print("nmapテスト開始")
    test_sudo_permissions()
    test_nmap_commands()
    print("\nテスト完了")