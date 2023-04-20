package check

import (
	"baseline/infra"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type RuleStruct struct {
	Type    string      `yaml:"type" bson:"type"`
	Param   []string    `yaml:"param" bson:"param"`
	Filter  string      `yaml:"filter" bson:"filter"`
	Require string      `yaml:"require" bson:"require"`
	Result  interface{} `yaml:"result" bson:"result"`
}

type BaselineCheck struct {
	Condition string       `yaml:"condition" bson:"condition"`
	Rules     []RuleStruct `yaml:"rules" bson:"rules"`
}

type CheckInfo struct {
	CheckId       int           `yaml:"check_id" bson:"check_id"`
	Type          string        `yaml:"type" bson:"type"`
	Title         string        `yaml:"title" bson:"title"`
	TitleCn       string        `yaml:"title_cn" bson:"title_cn"`
	Description   string        `yaml:"description" bson:"description"`
	Solution      string        `yaml:"solution" bson:"solution"`
	Security      string        `yaml:"security" bson:"security"`
	TypeCn        string        `yaml:"type_cn" bson:"type_cn"`
	DescriptionCn string        `yaml:"description_cn" bson:"description_cn"`
	SolutionCn    string        `yaml:"solution_cn" bson:"solution_cn"`
	Check         BaselineCheck `yaml:"check" bson:"check"`
}

type BaselineInfo struct {
	BaselineId      int         `yaml:"baseline_id" bson:"baseline_id"`
	BaselineVersion string      `yaml:"baseline_version" bson:"baseline_version"`
	CheckList       []CheckInfo `yaml:"check_list" bson:"check_list"`
}

const (
	SuccessCode      = 1
	FailCode         = 2
	ErrorCode        = -1
	ErrorConfigWrite = -2 // Configuration writing is not standardized
	ErrorFile        = -3 // File read and write exception
)

// StringMatch String match, including regular
// subStr : Returns a substring if the regular expression is grouped regular, otherwise ""
func StringMatch(str string, reg string) (subStr string, ifMatch bool, err error) {
	regCom, err := regexp.Compile(reg)
	if err != nil {
		return "", false, err
	}
	matchList := regCom.FindStringSubmatch(str)
	if len(matchList) == 0 {
		return "", false, err
	} else if len(matchList) == 1 {
		return "", true, err
	} else {
		return matchList[1], true, err
	}
}

// Handling rule relational operators
func DealMathCompute(funcRes interface{}, ruleRes string) (ifPass bool, err error) {
	reg := "\\$\\((.+)\\)"

	// Determine if a relational operator exists in a rule
	operator, ifMatch, err := StringMatch(ruleRes, reg)

	if ifMatch {
		// Convert both parties to int
		var (
			ruleInt int
			funcInt int
		)
		rule := ruleRes[len(operator)+3:]
		ruleInt, err = strconv.Atoi(rule)

		switch funcRes.(type) {
		case int:
			funcInt = funcRes.(int)
		case string:
			funcInt, err = strconv.Atoi(funcRes.(string))
			if err != nil {
				errStr := fmt.Sprintf("%d:need get num,but get %s", ErrorConfigWrite, funcRes)
				return ifPass, errors.New(errStr)
			}
		default:
			errStr := fmt.Sprintf("%d:need get num,but get unkown type", ErrorConfigWrite)
			return ifPass, errors.New(errStr)
		}

		// Logical operation
		switch operator {
		case "<":
			if funcInt < ruleInt {
				ifPass = true
			}
		case "<=":
			if funcInt <= ruleInt {
				ifPass = true
			}
		case ">":
			if funcInt > ruleInt {
				ifPass = true
			}
		case ">=":
			if funcInt >= ruleInt {
				ifPass = true
			}
		}
	}
	return ifPass, err
}

// Determine whether the rule result is passed
func ResultMatch(ruleStruct RuleStruct, funcRes interface{}) (ifPass bool, err error) {
	ruleRes := ruleStruct.Result

	if ruleRes == nil {
		ruleRes = true
	}

	funcType := reflect.TypeOf(funcRes).Kind()
	switch ruleRes.(type) {
	case bool:
		if funcType == reflect.Bool {
			if ruleRes == funcRes {
				return true, err
			} else {
				return false, err
			}
		} else {
			errStr := fmt.Sprintf("%d:rule is bool, but get other type", ErrorConfigWrite)
			return false, errors.New(errStr)
		}
	case int:
		// format
		if funcType == reflect.String {
			funcInt, err := strconv.Atoi(funcRes.(string))
			if err == nil {
				funcRes = funcInt
			} else {
				errStr := fmt.Sprintf("%d:rule is int,but get string : %s", ErrorConfigWrite, funcRes.(string))
				return false, errors.New(errStr)
			}
		} else if funcType == reflect.Int {
		} else {
			errStr := fmt.Sprintf("%d:rule is int, but get other type", ErrorConfigWrite)
			return false, errors.New(errStr)
		}

		// match
		if ruleRes == funcRes {
			return true, err
		} else {
			return false, err
		}
	case string:

		// Formatting rules and function results
		ruleString := ruleRes.(string)
		if funcType == reflect.Int {
			funcRes = strconv.Itoa(funcRes.(int))
			funcType = reflect.String
		} else if funcType == reflect.String {
		} else if funcType == reflect.Bool {
			return funcRes.(bool), err
		} else {
			errStr := fmt.Sprintf("%d:rule is string, but get other type", ErrorConfigWrite)
			return false, errors.New(errStr)
		}

		// Filter rules
		ruleFilter := ruleStruct.Filter
		subStr := ""
		if ruleFilter != "" && funcType == reflect.String {
			ifMatch := false
			subStr, ifMatch, err = StringMatch(funcRes.(string), ruleFilter)
			if err != nil || !ifMatch {
				errStr := fmt.Sprintf("%d:rule filter error : funcRes:%s, rule:%s", ErrorConfigWrite, funcRes.(string), ruleFilter)
				return ifPass, errors.New(errStr)
			}
		}

		// Handling logical operators
		var ruleArray []string
		if strings.Contains(ruleString, "$(&&)") {
			ruleArray = strings.Split(ruleString, "$(&&)")
		} else {
			ruleArray = append(ruleArray, ruleString)
		}

		// Traverse the subrules and return directly if false occurs
		for _, rule := range ruleArray {
			// Whether the result of this subrule is reversed $ (not)
			reverse := false
			if strings.HasPrefix(rule, "$(not)") {
				reverse = true
				rule = rule[len("$(not)"):]
			}

			// Determine if the subrules match
			if strings.HasPrefix(rule, "$(") {
				// Handling relational operators
				if subStr != "" {
					ifPass, err = DealMathCompute(subStr, rule)
				} else {
					ifPass, err = DealMathCompute(funcRes, rule)
				}
				if err != nil {
					return false, err
				}

			} else {
				// Ordinary regular matching
				// If the substring is not an int but a string, use substring matching
				_, err = strconv.Atoi(funcRes.(string))
				if err != nil {
					_, ifPass, err = StringMatch(subStr, rule)
				}
				if funcType == reflect.String {
					_, ifPass, err = StringMatch(funcRes.(string), rule)
				}
			}
			// Determine the result of the subrule, if one fails, it will directly return false.
			if reverse {
				ifPass = !ifPass
			}
			if ifPass == false {
				return false, err
			}
		}
	}

	ifPass = true
	return ifPass, err
}

// CheckRule check rule result
func CheckRule(ruleStruct RuleStruct) (ifPass bool, err error) {
	var funcRes interface{}

	// Determine if there are rule prerequisites
	if ruleStruct.Require != "" {
		switch ruleStruct.Require {
		default:
			break
		}
	}

	// Send to different matching functions according to type
	switch ruleStruct.Type {
	case "command_check":
		// Get command line results
		funcRes, err = CommandCheck(ruleStruct.Param)
	case "if_file_exist":
		// Determine if the file exists
		funcRes, err = IfFileExist(ruleStruct.Param)
	case "file_permission":
		// Determine whether file permissions are reasonable
		funcRes, err = FilePermission(ruleStruct.Param)
	case "file_user_group":
		// Determine if the file user group is reasonable
		funcRes, err = FileUserGroup(ruleStruct.Param)
	case "file_line_check":
		funcRes, err = FileLineCheck(ruleStruct, ResultMatch)
	case "func_check":
		funcRes, err = FuncCheck(ruleStruct.Param)
	case "file_md5_check":
		// Calculate whether the file MD5 is consistent
		funcRes, err = FileMd5Check(ruleStruct.Param)

	default:
		errStr := fmt.Sprintf("%d:unknown rule type:%s", ErrorConfigWrite, ruleStruct.Type)
		return false, errors.New(errStr)
	}
	if err != nil {
		infra.Loger.Println(err)
		return false, err
	}

	// if file_line_check，Match line by line
	switch ruleStruct.Type {
	case "file_line_check":
		ifPass = funcRes.(bool)
	default:
		ifPass, err = ResultMatch(ruleStruct, funcRes)
	}
	if err != nil {
		infra.Loger.Println(err)
		return false, err
	}

	return ifPass, err
}

// AnalysisRule Rule parsing engine
func AnalysisRule(check BaselineCheck) (ifPass bool, err error) {
	condition := check.Condition
	if condition == "" {
		condition = "all"
	}

	for _, rule := range check.Rules {
		ifCheck, err := CheckRule(rule)
		if err != nil {
			infra.Loger.Println(err)
			return false, err
		}
		if ifCheck {
			if condition == "any" {
				return true, err
			} else if condition == "none" {
				return false, err
			}
		} else {
			if condition == "all" {
				return false, err
			}
		}
	}

	if condition == "any" {
		return false, err
	} else {
		return true, err
	}
}
