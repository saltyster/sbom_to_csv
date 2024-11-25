import sys
import pandas as pd
import json
import csv

def main(sbom_json, compensate_csv, output_file):
    '''
    メイン
    githubでエクスポートしたSBOMのJSONファイルを"サードパーティ製コンポーネント管理表"へ
    転記できるCSVファイルに変換

    Parameter
        sbom_json : githubでエクスポートしたSBOMのJSONファイル
        compensate_csv : githubのSBOMで足りない項目を補うCSVファイル
        output_file : 出力先のCSVファイル "サードパーティ製コンポーネント管理表"へ転記用
    '''
    #SBOMのJSONファイルをフラット化(辞書配列化)
    sbom_dict = flatten_jsonfile(sbom_json,'packages', ',')
    #足りない項目を補うCSVの辞書配列化
    csv_dict = read_csv_to_dict(compensate_csv)

    #編集しやすい形に変換(pandas.DataFrameに変換し.Tで転置)
    sbom_t = pd.DataFrame.from_dict(sbom_dict).T
    csv_t = pd.DataFrame(csv_dict).T

    #SBOMのJSONと足りない項目を補うCSVをマージするための処理
    output_list = []
    for sbom_k, sbom_v in sbom_t.items():
        compensate_data = []
        for csv_k, csv_v in csv_t.items():
            #同一のパッケージ名があるか
            if sbom_v["name"] == csv_v["PackageName"]:
                compensate_data = csv_v
                break
        if any(compensate_data):
            #SBOMのJSONと足りない項目を補うCSVの両方にパッケージの情報がある場合
            output_list.append(get_from_github_sbom_and_compensate_csv(sbom_v, compensate_data))
        else:
            #SBOMのJSONにしかパッケージの情報がない場合
            output_list.append(get_from_github_sbom(sbom_v))

    #CSV出力
    pd.DataFrame.from_dict(output_list).to_csv(output_file, encoding='utf-8', index=False)

def flatten(data, parent_key='', sep='.'):
    '''
    JSONのフラット化
    JSON項目に配列が存在する場合は配列名と中身の項目名を使用して識別しやすい列名を生成し、配列もフラット化する

    Parameter
        data : フラット化するJSON
        parent_key : 配列内のデータを処理する場合、識別する列名の生成のために配列名を渡す
        sep : 区切り文字。配列内のデータを処理する場合、識別する列名の生成のために使用
    '''
    items = []
    for k, v in data.items():
        # 列名を作成
        new_key = parent_key + sep + k if parent_key else k

        if isinstance(v, dict):
            items.extend(flatten(v, new_key, sep=sep).items())
        # リスト項目のフラット化
        elif isinstance(v, list):
            new_key_tmp = new_key
            for i, elm in enumerate(v):
                new_key = new_key_tmp + sep + str(i)
                #
                if isinstance(elm, dict):
                    #識別しやすい名前を生成する場合
                    #items.extend(flatten(elm, new_key, sep=sep).items())
                    #識別しやすい名前を生成しなくても良い場合
                    items.extend(flatten(elm, sep=sep).items())
                else:
                    items.append((new_key, elm))
        # 値を追加
        else:
            items.append((new_key, v))
    return dict(items)

def flatten_jsonfile(json_file, rows_root, sep='.'):
    '''
    JSONのフラット化の前準備
    Parameter
        jsonfile : JSONファイルのパス
        rowsroot : フラット化する項目名。入力を空文字とすると頭からフラット化
        sep : 区切り文字。配列内のデータを処理する場合、識別する列名の生成のために使用
    '''
    with open(json_file, encoding='utf-8') as f:
        d = json.load(f)

    # フラット化する項目を指定
    if rows_root != '':
        d = d[rows_root]

    # 実際のフラット化はflatten()で実行
    dlist = []
    for di in d:
        dlist.append(flatten(di, sep=sep))

    # 試しにCSV出力
    #pd.DataFrame.from_dict(dlist).to_csv("out.csv", encoding='utf-8')
    return dlist

def read_csv_to_dict(csv_file):
    '''
    CSVファイルを読み込み、辞書配列に
    Parameter
        csv_file : CSVファイルのパス
    '''
    with open(csv_file, newline = "", encoding='utf-8') as f:
        read_dict = csv.DictReader(f, delimiter=",", quotechar='"')
        ks = read_dict.fieldnames
        dlist = {k: [] for k in ks}

        for row in read_dict:
            for k, v in row.items():
                dlist[k].append(v) # notice the type of the value is always string.

    #print(dlist)
    return dlist

def get_from_github_sbom_and_compensate_csv(github_sbom, compensate_csv):
    '''
    githubからのSBOMの内容と足りない項目を補うCSVの内容から"サードパーティ製コンポーネント管理表"へ記入する内容を作成
    Parameter
        github_sbom : githubからのSBOMの内容
        compensate_csv : 足りない項目を補うCSVの内容
    '''
    spdx = {}
    spdx['PackageName'] = github_sbom['name']
    spdx['SPDXID'] = github_sbom['SPDXID']
    if github_sbom.get('versionInfo'):
        spdx['PackageVersion'] = github_sbom['versionInfo']
    else:
        spdx['PackageVersion'] = compensate_csv['PackageVersion']

    spdx['PackageFileName'] = compensate_csv['PackageFileName']

    spdx['PackageSupplier'] = compensate_csv['PackageSupplier']

    if github_sbom.get('downloadLocation'):
        spdx['PackageDownloadLocation'] = github_sbom['downloadLocation']
    else:
        spdx['PackageDownloadLocation'] = compensate_csv['PackageDownloadLocation']

    if github_sbom.get('filesAnalyzed'):
        spdx['FilesAnalyzed'] = github_sbom['filesAnalyzed']
    else:
        spdx['FilesAnalyzed'] = compensate_csv['FilesAnalyzed']

    spdx['PackageHomePage'] = compensate_csv['PackageHomePage']

    if github_sbom.get('licenseConcluded'):
        spdx['PackageLicenseConcluded'] = github_sbom['licenseConcluded']
    else:
        spdx['PackageLicenseConcluded'] = compensate_csv['PackageLicenseConcluded']

    if github_sbom.get('PackageLicenseDeclared'):
        spdx['PackageLicenseDeclared'] = github_sbom['PackageLicenseDeclared']
    else:
        spdx['PackageLicenseDeclared'] = compensate_csv['PackageLicenseDeclared']

    spdx['PackageLicenseComments'] = compensate_csv['PackageLicenseComments']

    if github_sbom.get('copyrightText'):
        spdx['PackageCopyrightText'] = github_sbom['copyrightText']
    else:
        spdx['PackageCopyrightText'] = compensate_csv['PackageCopyrightText']

    spdx['PackageComment'] = compensate_csv['PackageComment']

    spdx['cpe23Type'] = compensate_csv['cpe23Type']

    #if github_sbom.get('externalRefs,0,referenceLocator'):
    #    spdx['purl'] = github_sbom['externalRefs,0,referenceLocator']
    if github_sbom.get('referenceLocator'):
        spdx['purl'] = github_sbom['referenceLocator']
    else:
        spdx['purl'] = compensate_csv['purl']

    spdx['advisory'] = compensate_csv['advisory']

    spdx['url'] = compensate_csv['url']

    spdx['LicenseID'] = compensate_csv['LicenseID']

    spdx['ExtractedText'] = compensate_csv['ExtractedText']

    spdx['LicenseName'] = compensate_csv['LicenseName']

    spdx['LicenseComment'] = compensate_csv['LicenseComment']

    spdx['Relationship'] = compensate_csv['Relationship']

    return spdx

def get_from_github_sbom(github_sbom):
    '''
    githubからのSBOMの内容から"サードパーティ製コンポーネント管理表"へ記入する内容を作成
    (足りない項目を補うCSV内にパッケージの情報が無い場合)
    Parameter
        github_sbom : githubからのSBOMの内容
    '''
    spdx = {}
    spdx['PackageName'] = github_sbom['name']
    spdx['SPDXID'] = github_sbom['SPDXID']
    if github_sbom.get('versionInfo'):
        spdx['PackageVersion'] = github_sbom['versionInfo']
    else:
        spdx['PackageVersion'] = ''
    spdx['PackageFileName'] = ''
    spdx['PackageSupplier'] = ''
    spdx['PackageDownloadLocation'] = github_sbom['downloadLocation']
    spdx['FilesAnalyzed'] = github_sbom['filesAnalyzed']
    spdx['PackageHomePage'] = ''
    if github_sbom.get('licenseConcluded'):
        spdx['PackageLicenseConcluded'] = github_sbom['licenseConcluded']
        spdx['PackageLicenseDeclared'] = github_sbom['licenseConcluded']
    else:
        spdx['PackageLicenseConcluded'] = ''
        spdx['PackageLicenseDeclared'] = ''
    spdx['PackageLicenseComments'] = ''
    if github_sbom.get('copyrightText'):
        spdx['PackageCopyrightText'] = github_sbom['copyrightText']
    else:
        spdx['PackageCopyrightText'] = ''
    spdx['PackageComment'] = ''
    spdx['cpe23Type'] = ''
    #spdx['purl'] = github_sbom['externalRefs,0,referenceLocator']
    spdx['purl'] = github_sbom['referenceLocator']
    spdx['advisory'] = ''
    spdx['url'] = ''
    spdx['LicenseID'] = ''
    spdx['ExtractedText'] = ''
    spdx['LicenseName'] = ''
    spdx['LicenseComment'] = ''
    spdx['Relationship'] = ''

    return spdx

if __name__ == '__main__':
    args = sys.argv
    if len(args) != 4:
        print(f'Usage: python {args[0]} github_sbom_file compensate_csv_file output_csv_file')
    else:
        main(args[1], args[2], args[3])
