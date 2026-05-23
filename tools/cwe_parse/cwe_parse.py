from XMLConfigure import Parents, Kids, get_all_ancestors, get_all_descendants


class CWENode:
    def __init__(self, cwe_id: str):
        self.cwe_id = cwe_id  # id-шник уязвимости из базы MITRE
        self.ancestors_dict: dict[str, list[str]] = {}  # Словарь для нахождения всех родителей на каждом уровне от cwe_id
        self.descendants_dict: dict[str, list[str]] = {}  # Словарь для нахождения всех детей на каждом уровне от cwe_id

        ancestors: list[tuple[str, int]] = get_all_ancestors(self.cwe_id, Parents)
        # Содержит список из пар, а каждая пара это {parent_id, height}, где parent_id это
        # родитель cwe_id на уровне height"""

        descendants: list[tuple[str, int]] = get_all_descendants(self.cwe_id, Kids)
        # Содержит список из пар, а каждая пара это {child_id, height}, где child_id это
        # ребёнок cwe_id на уровне height"""
        self.ancestors_dict["ALL"] = []  # С помощью ключа "ALL" можно достать абсолютно всех родителей на каждом из уровней
        self.descendants_dict["ALL"] = []  # С помощью ключа "ALL" можно достать абсолютно всех детей на каждом из уровней
        for ancestor_id, height in ancestors:
            self.ancestors_dict["ALL"].append(ancestor_id)
            if str(height) not in self.ancestors_dict:
                self.ancestors_dict[str(height)] = []
            self.ancestors_dict[str(height)].append(ancestor_id)

        for descendant_id, height in descendants:
            self.descendants_dict["ALL"].append(descendant_id)
            if str(height) not in self.descendants_dict:
                self.descendants_dict[str(height)] = []
            self.descendants_dict[str(height)].append(descendant_id)


    # С помощью поля level Можно получить родителей на уровне "level", если level = None,
    # достается ключ ALL который достаёт вообще всех детей
    def get_ancestors(self, level: str = None):
        if level is None:
            return self.ancestors_dict["ALL"]
        return self.ancestors_dict[level]


    # С помощью поля level Можно получить детей на уровне "level", если level = None,
    # достается ключ ALL, который достаёт вообще всех детей
    def get_descendants(self, level: str = None):
        if level is None:
            return self.descendants_dict["ALL"]
        return self.descendants_dict[level] if level in self.descendants_dict else []
