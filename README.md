# Name

githubでエクスポートできるSPDX Lite形式のSBOMをサードパーティ製コンポーネント管理表.xlsx
に転機しやすいCSVファイルに変換する

# Requirement

* pandas

# Installation

- 仮想環境作成  
`python -m venv [仮想環境名]`

- 仮想環境のアクティベート 
  - Linux, Macの場合  
    `.\[仮想環境名]\bin\activate`
  - Windowsの場合  
    `.\[仮想環境名]\Scripts\activate`

- pandasのインストール  
  `pip install pandas`


# Usage

```bash
python github_sbom_to_csv.py github_sbom_file compensate_csv_file output_csv_file
```
