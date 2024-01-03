# Fscan输出文件整理
最近使用fscan频繁，发现生成结果不是很清晰。 在Git找了个师傅写的现有脚本，发现有点bug 
且中文读取和显示貌似有点问题，代码可读性不是很好 我就直接重写了

动态显示和生成表格，不会显示和生成没有结果的项

## 使用
pip install -r requirements.txt `安装个别库失败的话 试试删除requirements中的版本限制`

python FscanOutputBeautif.py result.txt `推荐Py3.9+运行`

## BUG
如果出现bug,欢迎提交issues 顺便附带上报错截图和对应数据`去除下敏感信息就行` 方便我调试🫰🏻
<hr>

![image](https://github.com/yz1639/FscanOutputBeautify/assets/44149984/a643a667-0eaf-4d01-8704-5910ede51f5a)
![image](https://github.com/yz1639/FscanOutputBeautify/assets/44149984/a1cd0513-dbc0-4067-b71b-793c0de0517f)
![image](https://github.com/yz1639/FscanOutputBeautify/assets/44149984/eb2c9a5a-eab0-4704-920d-0c5457a2bedf)


