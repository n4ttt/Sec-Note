## 什么是Spring Boot？
Spring Boot 是由 Pivotal 团队提供的全新框架，其设计目的是用来简化新 Spring 应用的初始搭建以及开发过程。该框架使用了特定的方式来进行配置，从而使开发人员不再需要定义样板化的配置。用我的话来理解，就是 Spring Boot 其实不是什么新的框架，它默认配置了很多框架的使用方式，就像 Maven 整合了所有的 Jar 包，Spring Boot 整合了所有的框架。<br>
## Spring Boot有什么优点？
简单、快速、方便！
## 第一个Spring Boot项目
### （一）maven构建项目
- 1、访问https://start.spring.io/
- 2、选择maven project、Spring Boot版本、Project信息，点击generate下载项目代码
- 3、解压后，使用 IDEA导入项目，File -> New -> Model from Existing Source.. -> 选择解压后的文件夹 -> Finish，选择 Maven 一路 Next，OK done!
### （二）IDEA构建项目
- 1、选择 File -> New -> Project，弹出新建项目的框
- 2、选择 Spring Initializr，Next出现默认https://start.spring.io/ 的选项
- 3、继续Next出现跟上面一样的内容，填好后确定
### （三）项目结构介绍
**Spring Boot的项目结构共三个文件：**
- src/main/java           程序开发以及主程序入口
- src/main/resources      配置文件
- src/test/java           测试程序<br>

**另外，Spring Boot建议的项目结构如下：**
```java
com
  +- example
    +- myproject
      +- Application.java
      |
      +- model
      |  +- Customer.java
      |  +- CustomerRepository.java
      |
      +- service
      |  +- CustomerService.java
      |
      +- controller
      |  +- CustomerController.java
      |
```
- 1、Application.java 建议放到根目录下面,主要用于做一些框架配置
- 2、model 目录主要用于实体与数据访问层（Repository）
- 3、service 层主要是业务类代码
- 4、controller 负责页面访问控制<br>

上述默认配置简单方便、还可以自行修改；最后启动Application.java方法即可。
### （四）引入web模块
1、pom.xml中添加支持web的模块：
```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```
pom.xml 文件中默认有两个模块：<br>
- 核心模块：spring-boot-starter<br>
包括自动配置支持、日志和 YAML，如果引入了 spring-boot-starter-web web 模块可以去掉此配置，因为 spring-boot-starter-web 自动依赖了 spring-boot-starter。<br>
- 测试模块：spring-boot-starter-test<br>
包括 JUnit、Hamcrest、Mockito。<br><br>

2、编写 Controller 内容：
```java
@RestController
public class HelloWorldController {
    @RequestMapping("/hello")
    public String index() {
        return "Hello World";
    }
}
```
@RestController 的意思就是 Controller 里面的方法都以 json 格式输出，不用再写什么 jackjson 配置的了！<br><br>
3、启动主程序，打开浏览器访问http://localhost:8080<br>
### （五）单元测试
打开的src/test/下的测试入口，编写简单的 http 请求来测试；使用 mockmvc 进行，利用MockMvcResultHandlers.print()打印出执行结果。
```java
@RunWith(SpringRunner.class)
@SpringBootTest
public class HelloTests {

  
    private MockMvc mvc;

    @Before
    public void setUp() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup(new HelloWorldController()).build();
    }

    @Test
    public void getHello() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/hello").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(equalTo("Hello World")));
    }
}
```

## 总结
使用 Spring Boot 可以非常方便、快速搭建项目，使我们不用关心框架之间的兼容性，适用版本等各种问题，我们想使用任何东西，仅仅添加一个配置就可以，所以使用 Spring Boot 非常适合构建微服务。
