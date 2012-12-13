Este proyecto está dividido en 4 subproyectos:

- igz-oauth2-provider -> destinado a generar JAR para instalar en el provedor de servicios OAuth
- igz-oauth2-consumer -> destinado a generar JAR para instalar en el consumidor de servicios OAuth
- oauth2-client -> proyecto para pruebas de consumer
- oauth2-server -> proyecto para pruebas de provider

Los cuatro proyectos están metidos en un parent de maven, para poder ejecutar comandos sobre todos ellos a la vez (ejecutandolos desde la raiz del proyecto)

El proyecto destinado a ser proveedor, debe:
- Incluir en su classpath la dependecia a igz-oauth2-provider.jar
- Incluir en su classpath un .xml destinado a guardar clientes ( como el fichero oauth2_clients.xml en el proyecto de prueba oauth2-server)
- Incluir en su classpath un oauth2.properties con la clave oauth2.token.expires y el valor deseado

El proyecto destinado a ser consumer debe:
- Incluir en su classpath la dependecia a igz-oauth2-consumer.jar
- Incluir en su classpath un oauth2.properties con las claves que hay en el mismo fichero en el proyecto de prueba oauth2-client