# HomeWork 5 - User Authorization Service

##  Security Update: Transition from JWT to JWE
За основу была взята домашняя работа к 4 ВоркШопу, но
была улучшена система безопасности:
- **Раньше**: Использовались JWT-токены (подписанные, но не зашифрованные)
- **Теперь**: Используются JWE-токены с полным шифрованием

##  Запуск приложения

### Требуемые переменные окружения:
1. `JWE_SECRET` - 32-байтный ключ для шифрования (Base64-encoded)
2. `JWE_ACCESS_EXPIRATION_MIN` - время жизни access-токена (минуты)
3. `JWE_REFRESH_EXPIRATION_DAYS` - время жизни refresh-токена (дни)

### Способы запуска:

#### 1. Через командную строку (рекомендуется):
```bash
java -DJWE_SECRET="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" \
     -DJWE_ACCESS_EXPIRATION_MIN=15 \
     -DJWE_REFRESH_EXPIRATION_DAYS=7 \
     -jar target/authorization-0.0.1-SNAPSHOT.jar
