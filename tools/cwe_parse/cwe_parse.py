from XMLConfigure import Parents, Kids, get_all_ancestors, get_all_descendants

class CWENode:
    def __init__(self, cwe_id: str):
        self.cwe_id = cwe_id

        self.ancestors_dict: dict[str, list[str]] = {}
        self.descendants_dict: dict[str, list[str]] = {}

        ancestors: list[tuple[str, int]] = get_all_ancestors(self.cwe_id, Parents)
        descendants: list[tuple[str, int]] = get_all_descendants(self.cwe_id, Kids)

        self.ancestors_dict["ALL"] = []
        self.descendants_dict["ALL"] = []

        for ancestor_id, height in ancestors:
            self.ancestors_dict["ALL"].append(ancestor_id)
            if str(height) not in ancestors_dict:
                self.ancestors_dict[str(height)] = []
            self.ancestors_dict[str(height)].append(ancestor_id)

        for descendant_id, height in descendants:
            self.descendants_dict["ALL"].append(descedant_id)
            if str(height) not in descendants_dict:
                self.descendants_dict[str(height)] = []
            self.descendants_dict[str(height)].append(descedant_id)

    def get_ancestors(self, level: str = None):
        if level is None:
            return self.ancestors_dict["ALL"]
        return self.ancestors_dict[level]
    def get_descendants(self, level: str = None):
        if level is None:
            return self.descendants_dict["ALL"]
        return self.descendants_dict[level]

# Необходимо создать локальный файл (он почти не обновляется, смысла в хранении в БД нет)
#
# Там прописать для каждой вершины все уровни потомков, предков
# Чтобы все это работало быстро, в файлике все уровни вложенности уже прописываем

# P.S. будет достаточно мало записей, т.к. на каждом уровне нодов суммарно
# хранится не более тысячи записей

# Нужно сделать через @property get_descendants(level=None), get_ancestors(level=None), которые
# по уровню level: str будут давать все эти списки нодов (только их cwe_id, прочее не нужно)
