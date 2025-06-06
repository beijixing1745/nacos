
<img src="doc/Nacos_Logo.png" width="50%" syt height="50%" />

# Nacos: Dynamic  *Na*ming and *Co*nfiguration *S*ervice

[![Gitter](https://badges.gitter.im/alibaba/nacos.svg)](https://gitter.im/alibaba/nacos?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)   [![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Gitter](https://travis-ci.org/alibaba/nacos.svg?branch=master)](https://travis-ci.org/alibaba/nacos)
[![](https://img.shields.io/badge/Nacos-Check%20Your%20Contribution-orange)](https://opensource.alibaba.com/contribution_leaderboard/details?projectValue=nacos)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/alibaba/nacos)

-------

## What does it do

Nacos (official site: [nacos.io](https://nacos.io)) is an easy-to-use platform designed for dynamic service discovery and configuration and service management. It helps you to build cloud native applications and microservices platform easily.

Service is a first-class citizen in Nacos. Nacos supports almost all type of services，for example，[Dubbo/gRPC service](https://nacos.io/docs/latest/ecology/use-nacos-with-dubbo/), [Spring Cloud RESTFul service](https://nacos.io/docs/latest/ecology/use-nacos-with-spring-cloud/) or [Kubernetes service](https://nacos.io/docs/latest/quickstart/quick-start-kubernetes/).

Nacos provides four major functions.

* **Service Discovery and Service Health Check** 
    
    Nacos makes it simple for services to register themselves and to discover other services via a DNS or HTTP interface. Nacos also provides real-time health checks of services to prevent sending requests to unhealthy hosts or service instances.

* **Dynamic Configuration Management**
  
    Dynamic Configuration Service allows you to manage configurations of all services in a centralized and dynamic manner across all environments. Nacos eliminates the need to redeploy applications and services when configurations are updated, which makes configuration changes more efficient and agile.

* **Dynamic DNS Service**
    
    Nacos supports weighted routing, making it easier for you to implement mid-tier load balancing, flexible routing policies, flow control, and simple DNS resolution services in the production environment within your data center. It helps you to implement DNS-based service discovery easily and prevent applications from coupling to vendor-specific service discovery APIs.

* **Service and MetaData Management**
	
    Nacos provides an easy-to-use service dashboard to help you manage your services metadata, configuration, kubernetes DNS, service health and metrics statistics.
 

## Quick Start
It is super easy to get started with your first project.

### Deploying Nacos on cloud

You can deploy Nacos on cloud, which is the easiest and most convenient way to start Nacos. 

Use the following [Nacos deployment guide](https://cn.aliyun.com/product/aliware/mse?spm=nacos-website.topbar.0.0.0) to see more information and deploy a stable and out-of-the-box Nacos server.


### Start by the provided startup package

#### Step 1: Download the binary package 

You can download the package from the [latest stable release](https://github.com/alibaba/nacos/releases).  

Take release `nacos-server-1.0.0.zip` for example:
```sh
unzip nacos-server-1.0.0.zip
cd nacos/bin 
``` 

#### Step 2: Start Server

On the **Linux/Unix/Mac** platform, run the following command to start server with standalone mode: 
```sh
sh startup.sh -m standalone
```

On the **Windows** platform, run the following command to start server with standalone mode.  Alternatively, you can also double-click the `startup.cmd` to run NacosServer.
```
startup.cmd -m standalone
```

For more details, see [quick-start.](https://nacos.io/docs/latest/quickstart/quick-start/)

## Quick start for other open-source projects:
* [Quick start with Nacos command and console](https://nacos.io/docs/latest/quickstart/quick-start/)

* [Quick start with dubbo](https://nacos.io/docs/latest/ecology/use-nacos-with-dubbo/)

* [Quick start with spring cloud](https://nacos.io/docs/latest/ecology/use-nacos-with-spring-cloud/)

* [Quick start with kubernetes](https://nacos.io/docs/latest/quickstart/quick-start-kubernetes/)


## Documentation

You can view the full documentation from the [Nacos website](https://nacos.io/docs/latest/overview/).

You can also read this online eBook from the [NACOS ARCHITECTURE & PRINCIPLES](https://nacos.io/docs/ebook/kbyo6n/).

All the latest and long-term notice can also be found here from [GitHub notice issue](https://github.com/alibaba/nacos/labels/notice).

## Contributing

Contributors are welcomed to join Nacos project. Please check [CONTRIBUTING](./CONTRIBUTING.md) about how to contribute to this project.

### How can I contribute?

* Take a look at issues with tags marked [`good first issue`](https://github.com/alibaba/nacos/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22) or [`contribution welcome`](https://github.com/alibaba/nacos/issues?q=is%3Aopen+is%3Aissue+label%3A%22contribution+welcome%22).
* Answer questions on [issues](https://github.com/alibaba/nacos/issues).
* Fix bugs reported on [issues](https://github.com/alibaba/nacos/issues), and send us a pull request.
* Review the existing [pull request](https://github.com/alibaba/nacos/pulls).
* Improve the [website](https://github.com/nacos-group/nacos-group.github.io), typically we need
  * blog post
  * translation on documentation
  * use cases around the integration of Nacos in enterprise systems.

## Other Related Project Repositories

* [nacos-spring-project](https://github.com/nacos-group/nacos-spring-project) provides the integration functionality for Spring.
* [nacos-group](https://github.com/nacos-group) is the repository that hosts the eco tools for Nacos, such as SDK, synchronization tool, etc.
* [spring-cloud-alibaba](https://github.com/spring-cloud-incubator/spring-cloud-alibaba) provides the one-stop solution for application development over Alibaba middleware which includes Nacos.

## Contact

* [Gitter](https://gitter.im/alibaba/nacos): Nacos's IM tool for community messaging, collaboration and discovery.
* [Twitter](https://twitter.com/nacos2): Follow along for latest nacos news on Twitter.
* [Weibo](https://weibo.com/u/6574374908): Follow along for latest nacos news on Weibo (Twitter of China version).
* [Nacos Segmentfault](https://segmentfault.com/t/nacos): Get latest notice and prompt help from Segmentfault.
* Email Group:
     * users-nacos@googlegroups.com: Nacos usage general discussion.
     * dev-nacos@googlegroups.com: Nacos developer discussion (APIs, feature design, etc).
     * commits-nacos@googlegroups.com: Commits notice, very high frequency.
* Join us from DingDing(Group 1: 21708933(full), Group 2: 30438813(full), Group 3: 31222241(full), Group 4: 12810027056). 


<img src="https://img.alicdn.com/imgextra/i4/O1CN01MI7re41xTrZNdB7Yv_!!6000000006445-0-tps-974-1228.jpg" width="500">

## Enterprise Service
If you need Nacos enterprise service support, or purchase cloud product services, you can join the discussion by scanning the following DingTalk group. It can also be directly activated and used through the microservice engine (MSE) provided by Alibaba Cloud.
https://cn.aliyun.com/product/aliware/mse?spm=nacos-website.topbar.0.0.0

<img src="https://img.alicdn.com/imgextra/i3/O1CN01RTfN7q1KUzX4TcH08_!!6000000001168-2-tps-864-814.png" width="500">


## Download

- [Nacos Official Website](https://nacos.io/download/nacos-server)
- [GitHub Release](https://github.com/alibaba/nacos/releases)
  
## Who is using

These are only part of the companies using Nacos, for reference only. If you are using Nacos, please [add your company here](https://github.com/alibaba/nacos/issues/273) to tell us your scenario to make Nacos better.

![Alibaba Group](https://docs.alibabagroup.com/assets2/images/en/global/logo_header.png)
![虎牙直播](https://a.msstatic.com/huya/main/img/logo.png)
![ICBC](https://v.icbc.com.cn/userfiles/Resources/ICBC/shouye/images/2017/logo.png)
![爱奇艺](https://www.iqiyipic.com/common/fix/site-v4/sprite-headLogo-index.png)
![平安科技](https://img.alicdn.com/tfs/TB1pwi9EwHqK1RjSZJnXXbNLpXa-479-59.png) 
![华夏信财](https://img.alicdn.com/tfs/TB1MZWSEzDpK1RjSZFrXXa78VXa-269-69.png)
![优客工场](https://www.urwork.cn/public/images/ui/logo.png)
![贝壳找房](https://img.alicdn.com/tfs/TB1ebu.EAvoK1RjSZFwXXciCFXa-224-80.png)
![瑞安农村商业银行](https://img.alicdn.com/tfs/TB1lxu7EBLoK1RjSZFuXXXn0XXa-409-74.png)
![司法大数据](https://img.alicdn.com/tfs/TB1L16eEzTpK1RjSZKPXXa3UpXa-302-50.png)
![搜易贷](https://www.souyidai.com/www-style/images/logo.gif)
![平行云](https://img.alicdn.com/tfs/TB1OigyDyLaK1RjSZFxXXamPFXa-168-70.png)
![甘肃紫光](https://img.alicdn.com/tfs/TB1gJ4vIhTpK1RjSZR0XXbEwXXa-462-60.jpg)
![海云天](http://www.seaskylight.com/cn/uploadfiles/image/logo.png)
![Acmedcare+](https://img.alicdn.com/tfs/TB1DZWSEzDpK1RjSZFrXXa78VXa-240-62.png)
![北京天合互联信息有限公司](https://14605854.s21i.faiusr.com/4/ABUIABAEGAAg4OvkzwUo8b-qlwUwxQ449gM!300x300.png)
![上海密尔克卫化工](http://www.mwclg.com/static-resource/front/images/home/img_logo_nav.png)
![大连新唯](https://www.synwe.com/logo-full.png)
![立思辰](https://user-images.githubusercontent.com/10215557/51593180-7563af00-1f2c-11e9-95b1-ec2c645d6a0b.png)
![东家](https://img.alicdn.com/tfs/TB1zWW2EpYqK1RjSZLeXXbXppXa-262-81.png)
![上海克垚](http://www.sh-guiyao.com/images/logo.jpg)
![联采科技](http://www.lckjep.com:80//theme/img/logoTop.png)
![南京28研究所](https://img.alicdn.com/tfs/TB1G216EsbpK1RjSZFyXXX_qFXa-325-53.jpg)
![凤凰网-汽车](https://p1.ifengimg.com/auto/image/2017/0922/auto_logo.png)
![中化信息](http://www.sinochem.com/Portals/0/xinlogo.png)
![一点车](https://img.alicdn.com/tfs/TB1DXerNgDqK1RjSZSyXXaxEVXa-333-103.png)
![明传无线](https://img.alicdn.com/tfs/TB1VfOANgHqK1RjSZFPXXcwapXa-313-40.png)
![妙优车](https://img.alicdn.com/tfs/TB1lvCyNhTpK1RjSZFMXXbG_VXa-130-60.png)
![蜂巢](https://img.alicdn.com/tfs/TB1kY9qNgTqK1RjSZPhXXXfOFXa-120-50.png)
![华存数据](https://img.alicdn.com/tfs/TB1G.GBNbrpK1RjSZTEXXcWAVXa-234-65.png)
![数云](https://img.alicdn.com/tfs/TB1qsurNgDqK1RjSZSyXXaxEVXa-300-90.png)
![广通软件](https://img.alicdn.com/tfs/TB13aywNhTpK1RjSZR0XXbEwXXa-98-38.png)
![菜菜](https://img.alicdn.com/tfs/TB1xqmBNjTpK1RjSZKPXXa3UpXa-162-70.png)
![科蓝公司](https://img.alicdn.com/tfs/TB18DmINcfpK1RjSZFOXXa6nFXa-200-200.png)
![浩鲸](https://img.alicdn.com/tfs/TB15uqANXzqK1RjSZFoXXbfcXXa-188-86.png)
![未名天日语](https://img.alicdn.com/tfs/TB1mvmyNkvoK1RjSZPfXXXPKFXa-238-46.png)
![金联创](https://img.alicdn.com/tfs/TB1PSWsNmrqK1RjSZK9XXXyypXa-195-130.jpg)
![同窗链](https://img.alicdn.com/tfs/TB1k1qzNbvpK1RjSZFqXXcXUVXa-160-69.png)
![顺能](https://img.alicdn.com/tfs/TB1HdyvNmzqK1RjSZFLXXcn2XXa-143-143.jpg)
![百世快递](https://img.alicdn.com/tfs/TB1UdaGNgHqK1RjSZJnXXbNLpXa-277-62.png)
![汽车之家](https://img.alicdn.com/tfs/TB17OqENbrpK1RjSZTEXXcWAVXa-240-113.jpg)
![鲸打卡](https://img.alicdn.com/tfs/TB1q71ANkvoK1RjSZPfXXXPKFXa-257-104.png)
![时代光华](https://img.alicdn.com/tfs/TB1UzuyNhTpK1RjSZR0XXbEwXXa-201-86.jpg)
![康美](https://img.alicdn.com/tfs/TB19RCANgHqK1RjSZFPXXcwapXa-180-180.jpg)
![环球易购](https://img.alicdn.com/tfs/TB1iCGyNb2pK1RjSZFsXXaNlXXa-143-143.jpg)
![Nepxion](https://avatars0.githubusercontent.com/u/16344119?s=200&v=4)
![chigua](https://img.alicdn.com/tfs/TB1aUe5EpzqK1RjSZSgXXcpAVXa-248-124.png)
![宅无限](https://img.alicdn.com/tfs/TB1H9O5EAvoK1RjSZFNXXcxMVXa-221-221.jpg)
![天阙](https://img.alicdn.com/tfs/TB1rNq4EwHqK1RjSZFgXXa7JXXa-200-200.jpg)
![联合永道](https://img.alicdn.com/tfs/TB1CRAxDxYaK1RjSZFnXXa80pXa-190-190.jpg)
![明源云](https://img.alicdn.com/tfs/TB1.q14ErrpK1RjSZTEXXcWAVXa-219-219.jpg)
![DaoCloud](https://www.daocloud.io/static/Logo-Light.png)
![美菜](https://www.meicai.cn/img/logo.9210b6eb.jpg)
![松格科技](https://img5.tianyancha.com/logo/lll/3aad34039972b57e70874df8c919ae8b.png@!f_200x200)
![集萃智能](https://www.jsic-tech.com/Public/uploads/20191206/5de9b9baac696.jpg)
![吾享](https://www.wuuxiang.com/theme/images/common/logo1.png)
![拓深科技](http://www.tpson.cn/static/upload/image/20230111/1673427385140440.png)
![长亮科技](https://www.sunline.cn/u_file/fileUpload/2021-06/25/2021062586431.png)
![深圳易停车库](http://pmt2f499f.pic44.websiteonline.cn/upload/wv0c.png)
![武汉日创科技](http://www.dragonwake.cn/static/css/default/img/logo.png)
![易管智能](https://i4im-web.oss-cn-shanghai.aliyuncs.com/images/logo.png)
![云帐房](https://www.yunzhangfang.com/assets/img/logo.4096cf52.png)
![三诺生物](https://www.sinocare.com/sannuo/templates/web/img/bocweb-logo.svg)

郑州山水, 知氏教育
