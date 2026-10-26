# AltınKasam

Çok kullanıcılı altın portföy takibi: kullanıcı adı/şifre ile giriş, her kullanıcının kendi portföyü,
toplam ve ürün bazında kâr/zarar. Fiyatlar sedatascikuyumculuk.com/currencies adresinden çekilir.

## Render'a kurulum
1. Bir Postgres veritabanı oluşturun (Render Postgres veya Neon/Supabase gibi ücretsiz bir servis)
   ve bağlantı adresini (Internal/Connection URL) kopyalayın.
2. Bu klasörü GitHub'a yükleyin → Render: New → Blueprint → depoyu seçin.
3. İstendiğinde `DATABASE_URL` değerine Postgres adresini yapıştırın. `SECRET_KEY` otomatik üretilir.
4. Deploy bitince adresi açıp "Kayıt ol" ile hesap oluşturun.

Yerelde: `pip install -r requirements.txt && python app.py` (SQLite kullanır).
