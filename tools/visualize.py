import pandas as pd
import plotly.graph_objects as go


class Visualizer:
    """
    Класс для инкапсуляции логики построения аналитических графиков и диаграмм.
    """

    def __init__(self, output_dir: str = "output_charts") -> None:
        self.output_dir = output_dir
        import os
        os.makedirs(self.output_dir, exist_ok=True)

    # def draw_cwe_ecosystem_sankey(self, df: pd.DataFrame, filename: str = "sankey_cwe_flow.html") -> None:
    #     """
    #     Строит диаграмму Сэнки, показывающую перетекание уязвимостей
    #     из классов CWE -> в Экосистемы -> в конкретные Пакеты.
    #
    #     Ожидаемый формат df: колонки ['cwe_id', 'ecosystem', 'package_name', 'vuln_count']
    #     """
    #     if df.empty:
    #         print("[-] DataFrame пуст. Невозможно построить диаграмму Сэнки.")
    #         return
    #
    #     # 1. Собираем все уникальные названия узлов (вершин) по порядку
    #     # Мы добавляем префиксы, чтобы узлы с одинаковыми именами (если вдруг есть)
    #     # на разных слоях не склеивались.
    #     cwe_nodes = [f"CWE: {x}" for x in df['cwe_id'].unique()]
    #     eco_nodes = [f"Eco: {x}" for x in df['ecosystem'].unique()]
    #     pack_nodes = [f"Pack: {x}" for x in df['package_name'].unique()]
    #
    #     all_nodes = cwe_nodes + eco_nodes + pack_nodes
    #
    #     # 2. Создаем маппинг "Текстовое имя" -> "Целочисленный индекс"
    #     node_indices = {name: i for i, name in enumerate(all_nodes)}
    #
    #     # 3. Формируем списки связей (links) для Plotly
    #     sources: list[int] = []
    #     targets: list[int] = []
    #     values: list[int] = []
    #
    #     # Проходим по каждой строке датафрейма и создаем два ребра графа:
    #     # Ребро 1: CWE -> Ecosystem
    #     # Ребро 2: Ecosystem -> Package
    #     for _, row in df.iterrows():
    #         cwe_name = f"CWE: {row['cwe_id']}"
    #         eco_name = f"Eco: {row['ecosystem']}"
    #         pack_name = f"Pack: {row['package_name']}"
    #         weight = row['vuln_count']
    #
    #         # Связь CWE -> Ecosystem
    #         sources.append(node_indices[cwe_name])
    #         targets.append(node_indices[eco_name])
    #         values.append(weight)
    #
    #         # Связь Ecosystem -> Package
    #         sources.append(node_indices[eco_name])
    #         targets.append(node_indices[pack_name])
    #         values.append(weight)
    #
    #     # 4. Инициализируем объект графика Plotly
    #     fig = go.Figure(data=[go.Sankey(
    #         node=dict(
    #             pad=20,  # Отступ между узлами
    #             thickness=30,  # Толщина самих прямоугольников
    #             line=dict(color="black", width=0.5),
    #             label=all_nodes,  # Подписи узлов
    #             # Здесь можно добавить кастомную палитру цветов через color=[...]
    #         ),
    #         link=dict(
    #             source=sources,
    #             target=targets,
    #             value=values,
    #             # color = "rgba(200, 200, 200, 0.4)" # Можно сделать связи полупрозрачными
    #         )
    #     )])
    #
    #     # 5. Настраиваем внешний вид и сохраняем
    #     fig.update_layout(
    #         title_text="Поток уязвимостей: Классы CWE ➔ Экосистемы ➔ Пакеты",
    #         font_size=12,
    #         height=800  # Задаем высоту явно, чтобы большие деревья не сплющивались
    #     )
    #
    #     output_path = f"{self.output_dir}/{filename}"
    #     fig.write_html(output_path)
    #     print(f"[+] Диаграмма Сэнки успешно сохранена в: {output_path}")
#
#
# # ==========================================
# # Пример использования класса в коде:
# # ==========================================
# if __name__ == "__main__":
#     # Эмулируем DataFrame, который пришел из метода query() OSVDataClient
#     mock_data = pd.DataFrame({
#         'cwe_id': ['CWE-79', 'CWE-79', 'CWE-89', 'CWE-89', 'CWE-400'],
#         'ecosystem': ['PyPI', 'npm', 'PyPI', 'Go', 'npm'],
#         'package_name': ['django', 'react', 'sqlalchemy', 'gorm', 'lodash'],
#         'vuln_count': [45, 120, 30, 15, 80]
#     })
#
#     viz = Visualizer()
#     viz.draw_cwe_ecosystem_sankey(mock_data)
