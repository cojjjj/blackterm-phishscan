from abc import ABC, abstractmethod


class IntelligenceModule(ABC):
    name = "Base Module"

    @abstractmethod
    def run(self, target_data):
        pass