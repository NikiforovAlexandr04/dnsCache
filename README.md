# dnsCache
ДНС сервер прослушивающий 53 порт с кэшированием записей.
Обрабатывает записи типа A, AAAA, NS, PTR
Для запуска необходимо выполнить pip install -r requiments.txt
Затем запустить в различных процессах 
python server.py и python client.py
затем в процессе с запущенным клиеном можно выполнять запросы
Записи кэшируются в файле cache.json который изначально пуст
 # Присеры запуска
 ![image](https://user-images.githubusercontent.com/58898465/120538295-c38ff380-c3ff-11eb-9183-953d1be443e0.png)
