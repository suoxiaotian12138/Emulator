import random
from enum import unique

import numpy as np
from scipy.stats import gamma, exponweib, pareto, lognorm, weibull_min
from sklearn.metrics import mean_squared_error
# Embedding methods:
# 1. rule-based: map each symbol to a feature value using a predefined rule
# 2. replay: separate legitimate features into bins, and map each symbol to a feature value in the same bin
# 3. model-based: generate cdf for legitimate features, and map each symbol to a feature value based on the cdf
# 4. modulo: map each symbol to a feature value using modulo operation

# input: decimal codes, in one dimension
# output: features embedded with the codes

class Embedder:
    def __init__(self, one_dimensional_codes: list = None):
        self._one_dimensional_codes = one_dimensional_codes
        self._embedded_features = None
        self._anchors = None

    def set_one_dimentional_codes(self, one_dimensional_codes: list):
        self._one_dimensional_codes = one_dimensional_codes
    def get_embedded_features(self):
        return self._embedded_features
    def get_anchors(self):
        return self._anchors

    def fix_rule_generator(self, legitimate_features: list, unique_codes: list = None):
        rules = dict()
        unique_features = list(set(legitimate_features))
        if unique_codes is None:
            unique_codes = sorted(list(set(self._one_dimensional_codes)))
        for code in unique_codes:
            while True:
                random_feature = random.choice(unique_features)
                if random_feature not in rules.values():
                    rules[code] = random_feature
                    break
        return rules

    def codes_to_features_fix_rules(self, rules: dict):
        # Fixed embedding
        # code: a one-dimensional list of decimal codes
        # rules: {code: feature}
        embedded_features = []
        for code in self._one_dimensional_codes:
            if code in rules.keys():
                embedded_features.append(rules[code])
            else:
                raise ValueError(f"Code {code} not in the rules")
        self._embedded_features = embedded_features

    def sequence_generator_distribution(self, distribution: str = "poisson", length: int = 1000 * 1000, random_seed: int = 0, lam: float = 1000.0):
        np.random.seed(random_seed)
        if distribution == "poisson":
            size = length
            sequences = np.random.poisson(lam = lam, size = size)
        else:
            pass
        return sequences / 1000

    def codes_to_features_range_rules(self, rules: dict):
        # Range embedding
        # code: a one-dimensional list of decimal codes
        # rules: {code: [min, max]}
        embedded_features = []
        for code in self._one_dimensional_codes:
            if code in rules.keys():
                min_value, max_value = rules[code]
                embedded_features.append(random.uniform(min_value, max_value))
            else:
                raise ValueError(f"Code {code} not in the rules")
        self._embedded_features = embedded_features

    def _generate_replay_bins(self, legitimate_features: list, unique_codes: list):
        unique_symbols_count = len(unique_codes)
        delimiters = [np.percentile(legitimate_features, i * 100 / unique_symbols_count) for i in
                      range(1, unique_symbols_count)]
        # assert if delimiter is unique
        for i in range(1, len(delimiters)):
            if delimiters[i] == delimiters[i - 1]:
                raise ValueError(f"Delimiter {delimiters[i]} is not unique.")
        replay_bins = {}
        for i in range(unique_symbols_count):
            unique_code = unique_codes[i]
            if i == 0:
                replay_bins[unique_code] = [feature for feature in legitimate_features if feature < delimiters[i]]
            elif i == unique_symbols_count - 1:
                replay_bins[unique_code] = [feature for feature in legitimate_features if
                                              feature >= delimiters[i - 1]]
            else:
                replay_bins[unique_code] = [feature for feature in legitimate_features if
                                              feature >= delimiters[i - 1] and feature < delimiters[i]]
        return replay_bins

    def codes_to_features_replay(self, legitimate_features: list, unique_codes: list = None, error_tolerance: int = 45):
        # replay embedding, used by:
        # TRCTC: Cabuk S. Network covert channels: Design, analysis, detection, and elimination[D]. Purdue University, 2006.
        # codes: a one-dimensional list of decimal codes
        # legitimate_features: features extracted from background traffic (legitimate traffic)
        embedded_features = []
        unique_codes = sorted(list(set(self._one_dimensional_codes))) if unique_codes is None else unique_codes

        replay_bins = self._generate_replay_bins(legitimate_features, unique_codes)
        for code in self._one_dimensional_codes:
            f = np.random.uniform(np.percentile(replay_bins[code], error_tolerance), np.percentile(replay_bins[code], 100 - error_tolerance))
            embedded_features.append(f)
        self._embedded_features = embedded_features

    def _discrete_decimal_codes_to_continuized_codes(self, decimal_codes: list, modulo: int, rd_seed: int = 0):
        # Paper: Gianvecchio, Steven, et al. "Model-based covert timing channels: Automated modeling and evasion." Recent Advances in Intrusion Detection: 11th International Symposium, RAID 2008, Cambridge, MA, USA, September 15-17, 2008.
        # Return: continuous range from 0 to modulo
        num_all_possible_codes = len(list(set(decimal_codes)))
        random.seed(rd_seed)
        continuous_codes = []
        for i in range(len(decimal_codes)):
            continuous_codes.append((decimal_codes[i] / num_all_possible_codes + random.randint(0, modulo)) % modulo)
        return continuous_codes

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

    def codes_to_features_model(self, legitimate_features: list, window_size: int = 1000):
        # Model-based cdf embedding, used by:
        # Gianvecchio S, Wang H, Wijesekera D, et al. Model-based covert timing channels: Automated modeling and evasion[C]//Recent Advances in Intrusion Detection: 11th International Symposium, RAID 2008
        # covert codes into continuous (0, 1) range
        embedded_features = list()
        continuous_codes = self._discrete_decimal_codes_to_continuized_codes(self._one_dimensional_codes, 1)
        if len(legitimate_features) < len(self._one_dimensional_codes):
            print(f"we have {len(self._one_dimensional_codes)} codes, but only {len(legitimate_features)} feature points...")
        min_feature_code_length = min(len(self._one_dimensional_codes), len(legitimate_features)) # get the minimum length of codes and features
        for i in range(0, min_feature_code_length, window_size):
            code_window = continuous_codes[i: i + window_size]
            feature_window = legitimate_features[i: i + window_size]
            models_parameters = self._fit_models(feature_window)
            optimal_model = self._find_optimal_model(models_parameters, feature_window)
            optimal_model_parameters = models_parameters[optimal_model]
            for c in code_window:
                if optimal_model == "pareto":
                    embedded_features.append(pareto.ppf(c, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2]))
                elif optimal_model == "lognorm":
                    embedded_features.append(lognorm.ppf(c, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2]))
                elif optimal_model == "gamma":
                    embedded_features.append(gamma.ppf(c, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2]))
                elif optimal_model == "exponweib":
                    embedded_features.append(exponweib.ppf(c, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2], optimal_model_parameters[3]))
                elif optimal_model == "weibull_min":
                    embedded_features.append(weibull_min.ppf(c, optimal_model_parameters[0], optimal_model_parameters[1], optimal_model_parameters[2]))
                else:
                    raise ValueError("Invalid model name.")
        self._embedded_features = embedded_features

    def codes_to_features_modulo(self, legitimate_features: list, modulo: int, if_truncate: bool = False):
        # Modulo embedding, used by:
        # Shah G, Molina A, Blaze M. Keyboards and Covert Channels[C]//USENIX Security Symposium. 2006, 15: 64.
        if len(legitimate_features) < len(self._one_dimensional_codes):
            print(f"we have {len(self._one_dimensional_codes)} codes, but only {len(legitimate_features)} feature points...")
        max_possible_code = max(self._one_dimensional_codes)
        if max_possible_code >= modulo:
            raise ValueError(f"Max possible code {max_possible_code} is larger than modulo {modulo}. Could not ensure decoding accuracy.")
        embedded_features = []
        for i in range(min(len(self._one_dimensional_codes), len(legitimate_features))):
            code = self._one_dimensional_codes[i]
            feature = legitimate_features[i] // modulo * modulo + code
            if not if_truncate:
                if feature < legitimate_features[i]:
                    feature += modulo
            embedded_features.append(feature)

        self._embedded_features = embedded_features

    def codes_to_features_linear(self, legitimate_features: list, unique_codes: list = None, Delta: float = None, delta: float = None):
        if unique_codes is None:
            unique_codes = sorted(list(set(self._one_dimensional_codes)))
        if Delta is None or delta is None:
            Delta = min(legitimate_features)
            delta = max(legitimate_features) - min(legitimate_features) / (max(unique_codes) - min(unique_codes))

        embedded_features = []
        for code in self._one_dimensional_codes:
            embedded_features.append(code * delta + Delta)
        self._embedded_features = embedded_features

    def _cdf_to_value(self, cdf_dict: dict, cdf_value: float):
        # cdf_dict: {"value": [], "cdf": []}
        # cdf_value: the value of cdf
        assert cdf_value >= 0 and cdf_value <= 1, "CDF value must be in [0, 1]"
        for i in range(len(cdf_dict["cdf"])):
            if cdf_value <= cdf_dict["cdf"][i]:
                return cdf_dict["value"][i]
        return None

    def codes_to_features_cdf(self, cdf: dict):
        # CDF embedding
        # CDF format: {"value": [],  "cdf": []}
        assert cdf["cdf"][0] == 0 and cdf["cdf"][-1] == 1, "CDF must start with 0 and end with 1"
        assert len(cdf["cdf"]) == len(cdf["value"]), "CDF and value must have the same length"
        continuous_codes = self._discrete_decimal_codes_to_continuized_codes(self._one_dimensional_codes, 1)
        embedded_features = []
        for code in continuous_codes:
            feature = self._cdf_to_value(cdf, code)
            embedded_features.append(feature)
        self._embedded_features = embedded_features



    def generate_anchors(self, initial_anchor: int = 1, anchor_step: int = 1, last_anchor: int = None):
        # generate anchors for embedding
        # initial_anchor: the first anchor
        # anchor_step: the step between two anchors
        if last_anchor is None:
            last_anchor = initial_anchor + len(self._one_dimensional_codes) * anchor_step
        anchors = []
        for i in range(initial_anchor, last_anchor, anchor_step):
            anchors.append(i)
        self._anchors = anchors