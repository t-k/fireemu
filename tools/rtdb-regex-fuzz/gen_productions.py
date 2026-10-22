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
    names += ["string " + e for e in ["esc_n", "esc_t", "esc_r", "esc_b", "esc_f", "esc_v",
                                      "esc_0", "esc_octal", "esc_octal_long", "esc_x",
                                      "esc_x_short", "esc_u", "esc_u_short", "esc_identity",
                                      "esc_quote", "esc_dquote", "esc_backslash",
                                      "quote single", "quote double", "length"]]
    names += ["string continuation " + t for t in ["LF", "CR", "CRLF", "LS", "PS"]]
    names += ["string raw_terminator " + t for t in ["LF", "CR", "CRLF", "LS", "PS"]]
    names += ["num_int", "num_decimal", "num_leading_dot", "num_exp", "num_exp_signed",
              "num_hex", "num_octal", "num_08", "num_zero"]
    names += ["operator " + o for o in ["==", "!=", "===", "!==", "<=", ">=", "<", ">", "&&", "||"]]
    names += ["format " + p for p in ["after_backslash", "in_escape", "in_string_body",
                                      "in_number", "in_operator", "in_name", "in_regex",
                                      "after_regex_backslash", "in_flags"]]
    names += ["name " + n for n in ["start Lu", "start Ll", "start Lt", "start Lm", "start Lo",
                                    "start Nl", "start Sc", "start Pc", "part Mn", "part Mc",
                                    "part Nd", "part Pc", "part ignorable", "part ignorable_c1",
                                    "neither No", "neither No_fraction",
                                    "neither Other_Alphabetic", "neither So_letter",
                                    "neither astral_letter", "neither newer_than_java"]]
    names += ["name_place " + p for p in ["member", "variable", "inside"]]
    names += ["update --5", "update 5--1", "update 5", "update -", "update ++5",
              "update auth.uid--", "update data.val()--1"]
    names += ["regex_terminator " + t for t in ["LF", "CR", "CRLF", "LS", "PS"]]
    names += ["relation " + o for o in ["<", "<=", ">", ">="]]
    names += ["keyword_member " + m for m in ["length", "val", "child", "exists", "contains",
                                              "matches", "parent", "true", "null", "if",
                                              "return", "typeof", "auth", "now"]]
    names += ["comment_split " + c for c in ["/* a *", "true /", "1 /F* ", "'x'.ma", "/*F*/ ",
                                             "true /"]]
    if edges:
        names += ["edge " + e for e in ["|", ")", "*", "+", "?", "{", "{2}", "}", "()", "**",
                                        "\\\\", "{1,", "{,2}"]]
    return names
