import asyncio
import sys
from core.identity import get_local_ip, get_public_ip, encode_id_final, decode_id_final
from core.tor_service import TorManager
from client.session import PeerSession

SHARED_SECRET = b"my_super_secret_shared_key_32b!!"
DEFAULT_PORT = 5000

async def handle_incoming(transport):
    print("\n[+] تم اتصال الطرف الآخر بنجاح! يمكنكم التراسل الآن.")
    asyncio.create_task(receiver(transport))
    await sender(transport)

async def receiver(transport):
    try:
        while True:
            msg = await transport.read_message()
            print(f"\n[الطرف الآخر]: {msg}\n[أنت]: ", end="")
    except Exception:
        print("\n[-] انقطع الاتصال مع الطرف الآخر.")

async def sender(transport):
    loop = asyncio.get_event_loop()
    while True:
        msg = await loop.run_in_executor(None, input, "[أنت]: ")
        if msg.strip():
            try:
                await transport.send_message(msg)
            except Exception as e:
                print(f"[-] فشل إرسال الرسالة: {e}")
                break

async def start_host(session: PeerSession):
    print("\nاختر نوع الشبكة للربط:")
    print("1. شبكة محلية (LAN)")
    print("2. إنترنت مباشر (Public IP)")
    print("3. شبكة خفية عبر Tor (للتغلب على NAT/Firewall)")
    
    choice = input("خيارك (1-3): ").strip()
    
    if choice == "1":
        ip = get_local_ip()
        my_id = encode_id_final(ip, DEFAULT_PORT, SHARED_SECRET)
        print(f"\n[+] الـ ID المحلي الخاص بك: {my_id}")
    elif choice == "2":
        try:
            ip = get_public_ip()
            my_id = encode_id_final(ip, DEFAULT_PORT, SHARED_SECRET)
            print(f"\n[+] الـ ID العام الخاص بك: {my_id}")
        except Exception as e:
            print(f"[-] تعذر الحصول على IP العام: {e}")
            return
    elif choice == "3":
        print("[+] جاري الاتصال بـ Tor Daemon وإنشاء Onion Service...")
        tor = TorManager()
        if tor.connect():
            onion_addr = tor.create_onion(DEFAULT_PORT)
            print(f"\n[+] عنوان Tor الخاص بك: {onion_addr}")
            print("[!] شارك هذا العنوان مباشرة مع صديقك للاتصال عبر Tor.")
        else:
            print("[-] فشل الاتصال بـ Tor. التأكد من تشغيل خدمة Tor على الجهاز.")
            return

    print("[+] بانتظار اتصالات العميل...")
    server = await session.listen(DEFAULT_PORT, handle_incoming)
    async with server:
        await server.serve_forever()

async def start_client(session: PeerSession):
    target = input("\nأدخل الـ ID أو عنوان Tor (.onion) الخاص بصديقك: ").strip()
    print("[+] جاري محاولة الاتصال...")
    
    try:
        if target.endswith(".onion"):
            # الاتصال عبر Tor SOCKS Proxy (يتطلب إعداد السوكس في الجلسة)
            print("[+] جاري الاتصال عبر خدمة Tor...")
            # ينفذ الاتصال عبر العقدة
        else:
            transport = await session.connect(target)
            print("[+] تم الاتصال المباشر بنجاح!")
            asyncio.create_task(receiver(transport))
            await sender(transport)
    except Exception as e:
        print(f"[-] فشل الاتصال: {e}")

async def main():
    print("=" * 50)
    print("      مشروع P2P Secure Chat - النسخة المربوطة")
    print("=" * 50)
    print("1. إنشاء جلسة واستقبال اتصال (Host)")
    print("2. الاتصال بطرف آخر (Connect)")
    
    mode = input("اختر الوضع (1 أو 2): ").strip()
    session = PeerSession(SHARED_SECRET)

    if mode == "1":
        await start_host(session)
    elif mode == "2":
        await start_client(session)
    else:
        print("خيار غير صحيح.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[+] تم إغلاق التطبيق بأمان.")
