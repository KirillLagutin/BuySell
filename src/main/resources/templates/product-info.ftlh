<!DOCTYPE html>
<html>
<head>
    <title>BuySell</title>
</head>
<body>
    <h1>BuySell</h1><hr>
    <form action="/" method="get">
        <input type="submit" value="Назад"/>
    </form>
    <h4>Подробная информация о товаре</h4>
    <#list images as image>
        <img src="/images/${image.id}" height="60px"/><br><br>
    </#list>
    <b>Название товара: </b>${product.title}<br>
    <b>Описание товара: </b>${product.description}<br>
    <b>Цена: </b>${product.price}<br>
    <b>Город: </b>${product.city}<br>
    <b>Автор: </b>${product.user.name}<br>
    <b>Номер телефона: </b>${product.user.phoneNumber}<br>
    <hr>
    <form action="/product/delete/${product.id}" method="post">
        <input type="submit" value="Удалить товар"/>
    </form>
</body>
<html>