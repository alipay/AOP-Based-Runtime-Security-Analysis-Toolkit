# AOP-Based-Runtime-Security-Analysis-Toolkit

Aosanalyzer is an AOP-based runtime security analysis toolkit for Android applications. This tool is based on the idea of aspect-oriented security (aspect-oriented programming in security). It lets your monitor security and privacy sensitive API calls made by application. It's a powerful tool for seeing how applications work or for tracking down security and privacy issues that you have in your applications.

# Requirements

[frida](https://frida.re/docs/android/)

# Installation

```
npm run build
src/analyzer.py -h
```

# Usage

- Run analyzer.py to attach your application.
  ```
  src/analyzer.py <your_package_name>
  ```
- Run your application on the device as normal.
- Quit the program. The result will be written to `<your_package_name>.db`. You can use sqlite3 to check it.
