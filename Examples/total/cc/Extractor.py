import random
import numpy as np
from scipy.stats import gamma, exponweib, pareto, lognorm, weibull_min
from sklearn.metrics import mean_squared_error

class Extractor:
    def __init__(self, extracted_features: list = None, extracted_anchors: list = None):
        self._extracted_features = extracted_features
        self._extracted_anchors = extracted_anchors
        self._extracted_codes = None
        self._arranged_features = None

    def set_extracted_features(self, extracted_features: list):
        self._extracted_features = extracted_features

    def rearrange_features_by_anchor(self, initial_anchor: int, anchor_step: int, last_anchor: int):
        if self._extracted_anchors == None:
            self._arranged_features = self._extracted_features
            return
        assert len(self._extracted_features) == len(self._extracted_anchors)
        valid_feature_count = (last_anchor - initial_anchor) // anchor_step + 1
        anchored_features = list(zip(self._extracted_anchors, self._extracted_features))[:valid_feature_count]
        sorted_features = sorted(anchored_features, key = lambda x: x[0])
        possible_features = [feature for _, feature in sorted_features]
        arranged_features = []
        idx = 0
        for i in range(initial_anchor, last_anchor, anchor_step):
            if idx >= len(sorted_features):
                break
            if i != sorted_features[idx][0]:
                arranged_features.append(random.choice(possible_features))
            else:
                arranged_features.append(sorted_features[idx][1])
                idx += 1
        self._arranged_features = arranged_features

    def get_extracted_codes(self):
        return self._extracted_codes

    def features_to_codes_fix_rules(self, rules: dict, error_range: float = 1):
        # Fixed embedding
        # observed_features: features extracted from received traffic
        # rules: {code: feature}
        extracted_codes = []
        for feature in self._arranged_features:
            for code, rule in rules.items():
                if rule - error_range <= feature <= rule + error_range:
                    extracted_codes.append(code)
                    break
        self._extracted_codes = extracted_codes

    def features_to_codes_range_rules(self, rules: dict):
        # Range embedding
        # observed_features: features extracted from received traffic
        # rules: {code: [min, max]}
        extracted_codes = []
        for feature in self._arranged_features:
            for code, rule in rules.items():
                if rule[0] <= feature <= rule[1]:
                    extracted_codes.append(code)
                    break
        self._extracted_codes = extracted_codes

    def sequence_generator_distribution(self, distribution: str = "poisson", length: int = 1000 * 1000, random_seed: int = 0, lam: float = 1000.0):
        np.random.seed(random_seed)
        if distribution == "poisson":
            size = length
            sequences = np.random.poisson(lam = lam, size = size)
        else:
            pass
        return sequences/1000 # in seconds

    def _generate_replay_bins(self, legitimate_features: list, unique_codes: list):
        unique_codes_count = len(unique_codes)
        delimiters = [np.percentile(legitimate_features, i * 100 / unique_codes_count) for i in
                      range(1, unique_codes_count)]
        # assert if delimiter is unique
        for i in range(1, len(delimiters)):
            if delimiters[i] == delimiters[i - 1]:
                raise ValueError(f"Delimiter {delimiters[i]} is not unique.")

        replay_bins = {}
        for i in range(unique_codes_count):
            unique_code = unique_codes[i]
            if i == 0:
                replay_bins[unique_code] = [feature for feature in legitimate_features if feature < delimiters[i]]
            elif i == unique_codes_count - 1:
                replay_bins[unique_code] = [feature for feature in legitimate_features if
                                              feature >= delimiters[i - 1]]
            else:
                replay_bins[unique_code] = [feature for feature in legitimate_features if
                                              feature >= delimiters[i - 1] and feature < delimiters[i]]
        return replay_bins

    def _replay_bins_to_codebook(self, replay_bins: dict, min_value: float = 0.0, max_value: float = 1000.0):
        replay_codebook = {}
        for code, bin in replay_bins.items():
            replay_codebook[code] = [min(bin), max(bin)]
        # set the min and max value of the codebook
        # the first code
        first_code = list(replay_codebook.keys())[0]
        replay_codebook[first_code][0] = min_value
        # the last code
        last_code = list(replay_codebook.keys())[-1]
        replay_codebook[last_code][1] = max_value
        return replay_codebook

    def features_to_codes_replay(self, legitimate_features: list, unique_codes: list):
        extracted_codes = []
        replay_bins = self._generate_replay_bins(legitimate_features, unique_codes)
        replay_codebook = self._replay_bins_to_codebook(replay_bins)
        for feature in self._arranged_features:
            for code, bin in replay_codebook.items():
                if feature >= bin[0] and feature <= bin[1]:
                    extracted_codes.append(code)
                    break
        self._extracted_codes = extracted_codes

    def _fit_models(self, feature_sample: list):
        res = dict()
        feature_sample = [x for x in feature_sample if x > 0]
        # pareto
        b, loc, scale = pareto.fit(feature_sample, floc = 0)
        res["pareto"] = [b, loc, scale]
        # lognorm
        s, loc, scale = lognorm.fit(feature_sample, floc = 0)
        res["lognorm"] = [s, loc, scale]
        # gamma
        a, loc, scale = gamma.fit(feature_sample, floc = 0)
        res["gamma"] = [a, loc, scale]
        # exponweib
        a, c, loc, scale = exponweib.fit(feature_sample, floc = 0)
        res["exponweib"] = [a, c, loc, scale]
        # weib_min
        c, loc, scale = weibull_min.fit(feature_sample, floc = 0)
        res["weibull_min"] = [c, loc, scale]
        return res

    def _find_optimal_model(self, parameters: dict, feature_sample: list):
        RMSEs = dict()
        # pareto
        pareto_samples = [pareto.rvs(parameters["pareto"][0], parameters["pareto"][1], parameters["pareto"][2]) for x in
                          range(len(feature_sample))]
        RMSEs["pareto"] = mean_squared_error(pareto_samples, feature_sample)
        # lognorm
        lognorm_samples = [lognorm.rvs(parameters["lognorm"][0], parameters["lognorm"][1], parameters["lognorm"][2]) for
                           x in range(len(feature_sample))]
        RMSEs["lognorm"] = mean_squared_error(lognorm_samples, feature_sample)
        # gamma
        gamma_samples = [gamma.rvs(parameters["gamma"][0], parameters["gamma"][1], parameters["gamma"][2]) for x in
                         range(len(feature_sample))]
        RMSEs["gamma"] = mean_squared_error(gamma_samples, feature_sample)
        # exponweib_RMSE
        exponweib_samples = [
            exponweib.rvs(parameters["exponweib"][0], parameters["exponweib"][1], parameters["exponweib"][2],
                          parameters["exponweib"][3]) for x in range(len(feature_sample))]
        RMSEs["exponweib"] = mean_squared_error(exponweib_samples, feature_sample)
        # weibull_min_RMSE
        weibull_min_samples = [
            weibull_min.rvs(parameters["weibull_min"][0], parameters["weibull_min"][1], parameters["weibull_min"][2])
            for x in range(len(feature_sample))]
        RMSEs["weibull_min"] = mean_squared_error(weibull_min_samples, feature_sample)
        min_RMSE = list(RMSEs.keys())[list(RMSEs.values()).index(min(list(RMSEs.values())))]
        return min_RMSE

    def _continuized_codes_to_discrete_decimal_codes(self, continuous_codes: list, modulo: int, num_all_possible_codes: int,
                                                    rd_seed: int = 0):
        discrete_codes = []
        random.seed(rd_seed)
        for i in range(len(continuous_codes)):
            discrete_code = int(num_all_possible_codes * ((continuous_codes[i] - random.randint(0, modulo)) % modulo))
            discrete_codes.append(discrete_code)
        return discrete_codes

    def features_to_codes_model(self, legitimate_features: list, num_all_possible_codes: int, window_size: int = 1000):
        assert len(legitimate_features) >= len(self._arranged_features)
        continuous_codes = []
        for i in range(0, len(self._arranged_features), window_size):
            feature_window = legitimate_features[i: i + window_size]
            arranged_feature_window = self._arranged_features[i: i + window_size]
            models_parameters = self._fit_models(feature_window)
            optimal_model = self._find_optimal_model(models_parameters, feature_window)
            optimal_model_parameters = models_parameters[optimal_model]
            for f in arranged_feature_window:
                if optimal_model == "pareto":
                    continuous_code = pareto.cdf(f, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2])
                elif optimal_model == "lognorm":
                    continuous_code = lognorm.cdf(f, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2])
                elif optimal_model == "gamma":
                    continuous_code = gamma.cdf(f, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2])
                elif optimal_model == "exponweib":
                    continuous_code = exponweib.cdf(f, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2], optimal_model_parameters[3])
                elif optimal_model == "weibull_min":
                    continuous_code = weibull_min.cdf(f, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2])
                else:
                    raise ValueError("Invalid model name.")
                continuous_codes.append(continuous_code)
        extracted_codes = self._continuized_codes_to_discrete_decimal_codes(continuous_codes, 1, num_all_possible_codes)
        self._extracted_codes = extracted_codes

    def features_to_codes_modulo(self, modulo: int):
        extracted_codes = []
        for feature in self._arranged_features:
            extracted_codes.append(feature % modulo)
        self._extracted_codes = extracted_codes

    def features_to_codes_linear(self, legitimate_features: list, unique_codes: list, Delta: float = None, delta: float = None):
        if Delta is None or delta is None:
            Delta = min(legitimate_features)
            delta = max(legitimate_features) - min(legitimate_features) / (max(unique_codes) - min(unique_codes))

        extracted_codes = []
        for feature in self._arranged_features:
            extracted_codes.append(int((feature - Delta) / delta))
        self._extracted_codes = extracted_codes


    def _value_to_cdf(self, cdf_dict: dict, value: float):
        # cdf_dict: {"value": [], "cdf": []}
        # value: the value to be converted to cdf
        # return: the cdf value of the value
        if value < min(cdf_dict["value"]):
            return 0
        elif value > max(cdf_dict["value"]):
            return 1
        else:
            for i in range(len(cdf_dict["value"]) - 1):
                if value <= cdf_dict["value"][i]:
                    return cdf_dict["cdf"][i]



    def features_to_codes_cdf(self, cdf: dict, num_all_possible_codes: int):
        extracted_codes = []
        for feature in self._arranged_features:
            continuous_code = self._value_to_cdf(cdf, feature)
            extracted_code = self._continuized_codes_to_discrete_decimal_codes(continuous_code, 1, num_all_possible_codes)
            extracted_codes.append(extracted_code)
        self._extracted_codes = extracted_codes
