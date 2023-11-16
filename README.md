# Fscan输出文件整理
最近使用fscan频繁，发现生成结果不是很清晰。 找了个现有师傅写的脚本，发现有点bug 
且中文读取和显示貌似有点问题，代码可读性不是很好(师傅别骂我😢)我就直接重写了

动态显示和生成表格，不会显示和生成没有结果的项

## 使用
pip install -r requirements.txt `安装个别库失败的话 试试删除requirements中的版本限制`

python FscanOutputBeautif.py result.txt `推荐Py3.9+运行`

## BUG
如果出现bug,欢迎提交issues 顺便附带上报错截图和对数据`去除下敏感信息就行` 方便我调试🫰🏻


![image-20231116151716306](https://ltaicd.oss-cn-chengdu.aliyuncs.com/img/image-20231116151716306.png)
