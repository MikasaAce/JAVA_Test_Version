import os
import shutil
import glob
import random
from neo4j import GraphDatabase

csv_path = ''
import_path = '/var/lib/neo4j/import/'
node_path = '/var/lib/neo4j/import/nodes_*_cypher.csv'
edge_path = '/var/lib/neo4j/import/edges_*_cypher.csv'

class Cleardb:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def delete_all(self):
        result = self.driver.execute_query("""MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r""")
        return result


class Query:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def query_not_sent_over_ssl(self):
        result_1 = self.driver.execute_query("""MATCH (n:CALL{NAME:"<operator>.assignment"}) WHERE n.CODE CONTAINS "new Cookie" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query("""MATCH (n:CALL{NAME:"<operator>.assignment"}) WHERE n.CODE CONTAINS "new Cookie" MATCH (m:CALL{NAME:"setSecure"}) WHERE (n)-[*..2]-(m) AND toLower(m.CODE) CONTAINS "true" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1,result_2

    def query_hardcoded_password(self):
        result = self.driver.execute_query(
            """MATCH (n:CALL),(m:IDENTIFIER) WHERE (n.NAME = "<operator>.assignment" AND toLower(m.NAME) CONTAINS "password" AND (n)-[]-(m)) OR toLower(n.NAME) CONTAINS "password" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result

    def query_http_only_not_set(self):
        result_1 = self.driver.execute_query("""MATCH (n:CALL) WHERE n.CODE CONTAINS "new Cookie" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query("""MATCH (n:CALL) WHERE n.CODE CONTAINS "new Cookie" MATCH (m:CALL{NAME:"setHttpOnly"}) WHERE (n)-[*..2]-(m) AND toLower(m.CODE) CONTAINS "true" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1, result_2

    def query_json_injection(self):
        result = self.driver.execute_query("""MATCH (n:CALL) WHERE n.CODE CONTAINS "objectMapper.readValue" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result

    def query_query_unsafe_json_deserialization(self):
        result_1 = self.driver.execute_query("""MATCH (n:CALL{NAME:"parseObject"})-[r:ARGUMENT]->(m:IDENTIFIER) RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query("""MATCH (n:CALL{NAME:"parseObject"})-[:ARGUMENT]->(m:IDENTIFIER) MATCH (l:LOCAL) WHERE l.NAME = m.NAME RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1,result_2


class ModifyNode:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def modify_node_source(self,source_filename):
        rand_offset = random.randint(0,999999999)
        cypher_clause = f'MATCH (n) WHERE n.SOURCEFILE IS NULL SET n.SOURCEFILE = "{source_filename}", n.id = n.id + {rand_offset} RETURN n'
        # noinspection PyTypeChecker
        result = self.driver.execute_query(cypher_clause)
        return result


def clear_database():
    clear_db = Cleardb("bolt://127.0.0.1:7687", "neo4j", "password")
    query_result = clear_db.delete_all()
    clear_db.close()


def set_sourcefile(filename):
    set_source = ModifyNode("bolt://127.0.0.1:7687", "neo4j", "password")
    query_result = set_source.modify_node_source(filename)
    set_source.close()


def copy_file(source_path):
    if os.path.exists(source_path):
        files = os.listdir(import_path)
        for file in files:
            os.remove(import_path + file)
        files = os.listdir(source_path)
        for file in files:
            shutil.copy(source_path + file, import_path)
    else:
        print('指定目录不存在')


def import_file():
    node_list = glob.glob(node_path)

    for node in node_list:
        print(node)
        import_node = f'/usr/share/cypher-shell/bin/cypher-shell -u neo4j -p password -f {node}'
        os.system(import_node)

    edge_list = glob.glob(edge_path)

    for edge in edge_list:
        print(edge)
        import_edge = f'/usr/share/cypher-shell/bin/cypher-shell -u neo4j -p password -f {edge}'
        os.system(import_edge)


def gen_csv_from(dir_path):
    if os.path.exists(csv_path):
        shutil.rmtree(csv_path)
    os.mkdir(csv_path)

    for filepath, dirs, filenames in os.walk(dir_path):
        for filename in filenames:
            command_parse = '/home/public/joern/joern-cli/joern-parse ' + os.path.join(filepath, filename)
            command_export = '/home/public/joern/joern-cli/joern-export --repr=all --format=neo4jcsv --out ' + os.path.join(
                csv_path, filename)
            if os.path.exists(os.path.join(filepath, filename)):
                os.system(command_parse)
                if os.path.exists(os.path.join(csv_path, filename)):
                    print("Remove origin")
                    shutil.rmtree(os.path.join(csv_path, filename))
                os.system(command_export)
            else:
                print("Dir not found")


def query_for_vul(csv_dir):
    clear_database()
    for dir_name in os.listdir(csv_dir):
        print(dir_name)
        copy_file(os.path.join(csv_dir, dir_name + '/'))
        import_file()
        set_sourcefile(dir_name.replace('#', '/'))

    querying = Query("bolt://127.0.0.1:7687", "neo4j", "password")

    # Cookie Security: Cookie not Sent Over SSL
    print('Cookie Security: Cookie not Sent Over SSL:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_not_sent_over_ssl()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Cookie Security: Cookie not Sent Over SSL   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
    else:
        print('No issue')

    print(total)
    print(final_result)

    # Password Management: Hardcoded Password
    print('Password Management: Hardcoded Password:')
    total = 0
    final_result = []
    query_result = querying.query_hardcoded_password()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Password Management: Hardcoded Password   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
    else:
        print('No issue')

    print(total)
    print(final_result)

    # Cookie Security: HTTPOnly not Set
    print('Cookie Security: HTTPOnly not Set:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_http_only_not_set()
    # querying.close()
    query_result_line = []
    query_result_code = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            query_result_line.remove(record)
            print(
                f'Cookie Security: HTTPOnly not Set   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
    else:
        print('No issue')

    print(total)
    print(final_result)

    # JSON Injection
    print('JSON Injection:')
    total = 0
    final_result = []
    query_result = querying.query_json_injection()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'JSON Injection   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
    else:
        print('No issue')

    print(total)
    print(final_result)

    # Dynamic Code Evaluation: Unsafe JSON Deserialization
    print('Dynamic Code Evaluation: Unsafe JSON Deserialization:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_query_unsafe_json_deserialization()
    query_result_line = []
    query_result_code = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Dynamic Code Evaluation: Unsafe JSON Deserialization   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
    else:
        print('No issue')

    print(total)
    print(final_result)

    querying.close()