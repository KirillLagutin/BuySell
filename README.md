# BuySell
## (Java, SpringBoot, MySql-cloud, Docker)

I. Введение
-------------------------

A. Цель: 
 Разработать простое и удобное веб-приложение, которое позволит пользователям размещать свои товары и услуги,
и также просматривать товары и услуги других пользователей.

B. Описание проекта: 
 Веб-приложение BuySell будет включать в себя функционал для поиска товаров и услуг, и размещения объявлений в своём личном кабинете.
============================================================================

II. Обзор SpringBoot
-------------------------------

A. SpringBoot: 
 Упрощенный фреймворк для разработки Spring-based приложений, позволяющий сократить время разработки и упростить процесс развертывания приложения.

B. Преимущества SpringBoot: 
 Меньшие объемы кода благодаря встроенным компонентам и автоконфигурации, быстрая разработка благодаря автоматическому конфигурированию и простому развертыванию.
=============================================================================

III. Архитектура веб-приложения
------------------------------------------------

A. Определение требований к веб-приложению: 
 Простота использования, безопасность, масштабируемость, производительность.

B. Проектирование структуры веб-приложения: 
 Использование шаблона проектирования MVC, разделение на модули (сервисы, контроллеры, представления).

C. Выбор технологий и инструментов для реализации веб-приложения: 
SpringBoot, Maven; 
Spring Web, Spring Security, Spring Data JPA, MySql Driver, Lombok, Freemarker, Bootstrap.
================================================================================

IV. Разработка веб-приложения
-----------------------------------------------

A. Реализация функционала веб-приложения: 
 Регистрация и авторизация пользователей, поиск товаров и услуг, покупка и продажа, отслеживание заказов.

B. Использование SpringSecurity для обеспечения безопасности и защиты данных пользователей.

C. Использование SpringData для работы с базами данных и доступа к данным.

D. Тестирование веб-приложения, обеспечение качества и надежности работы приложения.
==================================================================================

V. Результаты и выводы
----------------------------------------

A. Подведение итогов проделанной работы, выявление и обсуждение проблем, с которыми пришлось столкнуться в процессе разработки.

B. Представление полученных результатов: 
 Успешно работающее веб-приложение с необходимым функционалом, соответствующее поставленным требованиям.
===================================================================================

VI. Заключение
------------------------

A. Итоги и выводы по дипломной работе, подведение итогов исследования.
===================================================================================


### Запуск в Docker (при условии запущенного докера)...

### Описание шагов по запуску проекта

  ### 1. В терминале, из папки проекта, прописываем команду для создания образа: 
  
      docker build -t docker-buysell:1.0-SNAPSHOT .
      
  ### 2. После успешной сборки запускаем образ: 
  
      docker run -d -p 8888:8080 docker-buysell:1.0-SNAPSHOT

  ### 3. Переходим на главную страницу сайта BuySell
  
      localhost:8888/docs
 
