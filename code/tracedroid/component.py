from dataclasses import field, dataclass


@dataclass
class Component:
    id: int = field(
        default=None, metadata={"desc": "Id of the component"}
    )
    name: str = field(
        default=None, metadata={"desc": "Description of the component"}
    )
    bound: list = field(
        default=None, metadata={"desc": "Bound of the component"}
    )
    cls_name: str = field(
        default=None, metadata={"desc": "Class name of component"}
    )
    text: str = field(
        default=None, metadata={"desc": "Text of component"}
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'bound': self.bound,
            'cls_name': self.cls_name,
            'text': self.text,
        }

    def match_keywords(self, keywords):
        target = ' '.join([str(self.name), str(self.cls_name), str(self.text)]).lower()
        for kw in keywords:
            if kw and kw.lower() in target:
                return True
        return False