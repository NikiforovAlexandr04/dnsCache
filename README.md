# dnsCache
ДНС сервер прослушивающий 53 порт с кэшированием записей.
Обрабатывает записи типа A, AAAA, NS, PTR
Для запуска необходимо выполнить pip install -r requiments.txt
Затем запустить в различных процессах 
python server.py и python client.py
затем в процессе с запущенным клиеном можно выполнять запросы
Записи кэшируются в файле cache.json который изначально пуст
 # Примеры запуска
 ![image](https://user-images.githubusercontent.com/58898465/130331476-2ff33e8b-d5f0-4109-8654-d83861b3d9ce.png)

# В процессе работы записи кэшируются в файл cache.json
![image](https://user-images.githubusercontent.com/58898465/130331455-9dd7a82a-8fa4-4885-b682-99f67030f599.png)
