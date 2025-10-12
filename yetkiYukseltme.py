import os
import sys
import pwd
import grp
import subprocess
from getpass import getpass

def check_current_user():
    current_user = pwd.getpwuid(os.getuid()).pw_name
    print(f"Mevcut kullanıcı: {current_user}")
    return current_user

def attempt_privilege_escalation():
    print("Güvenlik kontrolü yapılıyor...")
    
    # Sudo yetkisi kontrolü
    try:
        sudo_test = subprocess.run(['sudo', '-n', 'true'], 
                                 stderr=subprocess.PIPE, 
                                 stdout=subprocess.PIPE)
        if sudo_test.returncode == 0:
            print("Sudo yetkileri mevcut, root erişimi deneniyor...")
            try:
                subprocess.run(['sudo', 'su'], check=True)
                return True
            except subprocess.CalledProcessError:
                print("Sudo ile root erişimi başarısız.")
        else:
            print("Sudo yetkisi yok veya şifre gerekiyor.")
    except FileNotFoundError:
        print("Sudo komutu bulunamadı.")
    
    # SUID bit kontrolü
    print("SUID bit kontrolü yapılıyor...")
    try:
        suid_files = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f'], 
                                  stderr=subprocess.PIPE, 
                                  stdout=subprocess.PIPE, 
                                  text=True)
        if suid_files.returncode == 0 and '/bin/su' in suid_files.stdout:
            print("SUID biti ayarlanmış dosyalar bulundu.")
            # Burada teorik olarak exploitable SUID binary'leri kontrol edilebilir
        else:
            print("Exploitable SUID binary bulunamadı.")
    except:
        print("SUID kontrolü başarısız.")
    
    return False

def main():
    print("Gelişmiş Yetki Yükseltme Aracı")
    print("------------------------------")
    
    current_user = check_current_user()
    
    if current_user == "root":
        print("Zaten root kullanıcısısınız!")
        return
    
    print("Root erişimi deneniyor...")
    
    # 1. Sudo ile deneme
    print("\n1. Yöntem: Sudo ile root erişimi")
    if attempt_privilege_escalation():
        return
    
    # 2. SUID exploit denemesi (teorik)
    print("\n2. Yöntem: SUID Exploit Kontrolü")
    print("Bu kısım teorik olarak exploitable binary'leri kontrol eder.")
    # Gerçek exploit kodu buraya eklenmez (yasal nedenlerle)
    
    # 3. Kernel exploit kontrolü
    print("\n3. Yöntem: Kernel Sürüm Kontrolü")
    try:
        kernel_info = subprocess.run(['uname', '-a'], 
                                   stdout=subprocess.PIPE, 
                                   text=True)
        print(f"Kernel bilgisi: {kernel_info.stdout.strip()}")
        print("Bilinen kernel açıkları için kontrol yapılabilir.")
        # Gerçek exploit kodu buraya eklenmez
    except:
        print("Kernel bilgisi alınamadı.")
    
    print("\nRoot erişimi başarısız oldu. Lütfen yöneticinize başvurun.")

if __name__ == "__main__":
    if os.name != 'posix':
        print("Bu script yalnızca Linux/Unix sistemlerde çalışır!")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nİşlem kullanıcı tarafından iptal edildi.")
        sys.exit(0)
    except Exception as e:
        print(f"Beklenmeyen bir hata oluştu: {str(e)}")
        sys.exit(1)
