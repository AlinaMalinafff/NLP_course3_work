from joblib import load
from sentence_transformers import SentenceTransformer
from scipy.sparse import hstack, csr_matrix
import re
from pymorphy2 import MorphAnalyzer

morph = MorphAnalyzer()
RUSSIAN_STOP_WORDS = {'и', 'в', 'во', 'не', 'что', 'он', 'на', 'я', 'с', 'со', 'как', 'а', 'то', 'все', 'она', 'так', 'его', 'но', 'да', 'ты', 'к', 'у', 'же', 'вы', 'за', 'бы', 'по', 'только', 'ее', 'мне', 'было', 'вот', 'от', 'меня', 'еще', 'нет', 'о', 'из', 'ему', 'теперь', 'когда', 'даже', 'ну', 'вдруг', 'ли', 'если', 'уже', 'или', 'ни', 'быть', 'был', 'него', 'до', 'вас', 'нибудь', 'опять', 'уж', 'вам', 'ведь', 'там', 'потом', 'себя', 'ничего', 'ей', 'может', 'они', 'тут', 'где', 'есть', 'надо', 'ней', 'для', 'мы', 'тебя', 'их', 'чем', 'была', 'сам', 'чтоб', 'без', 'будто', 'чего', 'раз', 'тоже', 'себе', 'под', 'будет', 'ж', 'тогда', 'кто', 'этот', 'того', 'потому', 'этого', 'какой', 'совсем', 'ним', 'здесь', 'этом', 'один', 'почти', 'мой', 'тем', 'чтобы', 'нее', 'сейчас', 'были', 'куда', 'зачем', 'всех', 'никогда', 'можно', 'при', 'наконец', 'два', 'об', 'другой', 'хоть', 'после', 'над', 'больше', 'тот', 'через', 'эти', 'нас', 'про', 'всего', 'них', 'какая', 'много', 'разве', 'три', 'эту', 'моя', 'впрочем', 'хорошо', 'свою', 'этой', 'перед', 'иногда', 'лучше', 'чуть', 'том', 'нельзя', 'такой', 'им', 'более', 'всегда', 'конечно', 'всю', 'между'}

def lemmatize_text(text):
    words = re.findall(r'\w+', text.lower())
    return [morph.parse(word)[0].normal_form for word in words if word not in RUSSIAN_STOP_WORDS]


class Model():
    def __init__(self):
        self._tfidf = None
        self._distilbert = None
        self._random_forest = None

    def load_models(self):
        self._tfidf = load('tfidf(1).joblib')
        self._distilbert = SentenceTransformer('model1/')
        self._random_forest = load('rf(1).joblib')

    def predict(self, text):
        if not all([self._tfidf, self._distilbert, self._random_forest]):
            self.load_models()
            print("Loaded models")
        tfifd_vector = self._tfidf.transform([text])
        distilbert_embed = self._distilbert.encode(text)
        combined_input = hstack([tfifd_vector, csr_matrix(distilbert_embed)])
        return self._random_forest.predict(combined_input)

