"""The grammar productions gen.py must generate in every round (see check_coverage.py)."""


def required(edges=False):
    names = [
        "literal_letter", "literal_digit", "literal_punctuation", "literal_non_ascii",
        "class", "class_negated", "class_range", "class_first_bracket", "dot", "group",
        "group_alternation", "empty_group", "flag_i", "flag_none", "subject_empty",
        "q_star", "q_plus", "q_opt", "q_count", "q_count_range", "q_count_open",
        "q_plus_opt", "q_star_opt", "q_opt_opt", "q_count_opt", "q_range_opt",
        "q_star_star", "q_plus_star", "q_count_count", "q_opt_plus", "q_count_plus",
        "top_alternation unanchored", "top_alternation start_anchored",
        "top_alternation end_anchored", "top_alternation anchored",
        "comment /*", "comment /**/", "comment //",
    ]
    names += ["escape " + e for e in ["\\w", "\\d", "\\s", "\\S", "\\W", "\\D", "\\.", "\\-",
                                      "\\]", "\\\\", "\\[", "\\^", "\\$", "\\*", "\\+", "\\?",
                                      "\\(", "\\)", "\\|", "\\{"]]
    names += ["class_escape " + e for e in ["\\w", "\\d", "\\s", "\\W", "\\D", "\\-", "\\]",
                                            "\\\\", "\\\\a", "\\\\]", "\\^"]]
    names += ["space U+%04X" % c for c in [0x20, 0x09, 0x0B, 0x0C, 0xA0, 0x1680, 0x2003,
                                           0x202F, 0x3000, 0xFEFF, 0x180E, 0x200B, 0xAD,
                                           0x2060, 0x85, 0x0A, 0x0D, 0x2028]]
    if edges:
        names += ["edge " + e for e in ["|", ")", "*", "+", "?", "{", "{2}", "}", "()", "**",
                                        "\\\\", "{1,", "{,2}"]]
    return names
