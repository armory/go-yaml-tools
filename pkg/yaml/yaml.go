package yaml

import (
	"strconv"

	"github.com/imdario/mergo"
	log "github.com/sirupsen/logrus"
)

//Resolve takes an array of yaml maps and returns a single map of a merged
//properties.  The order of `ymlTemplates` matters, it should go from lowest
//to highest precendence.
func Resolve(ymlTemplates []map[string]interface{}, envKeyPairs []string) map[string]string {
	log.Debugf("Using environ %+v\n", envKeyPairs)

	mergeMap := map[string]interface{}{}

	for _, yml := range ymlTemplates {
		if err := mergo.Merge(&mergeMap, yml); err != nil {
			log.Error(err)
		}
	}

	flatMap := map[string]string{}
	//we flatten the map to easily lookup keys
	flatten(true, flatMap, ymlTemplates[0], "")

	return flatMap
	//  keep_resolving = True
	//  loops = 0
	//  while keep_resolving and loops < len(flattened):
	// 		 loops += 1
	// 		 keep_resolving = False
	// 		 for key, value in flattened.items():
	// 				 keys_to_resolve = re.findall("\$\{(.*?)\}", str(value))
	// 				 if len(keys_to_resolve) > 0: keep_resolving = True
	// 				 resolved_keys = _resolve_key_substition(flattened, keys_to_resolve)
	// 				 for sub_key, resolved_key in resolved_keys:
	// 						 flattened[key] = flattened[key].replace(
	// 												 "${%s}" % sub_key, str(resolved_key))
	//  return flattened

}

func flatten(top bool, flatMap map[string]string, nested interface{}, prefix string) error {
	assign := func(newKey string, v interface{}) error {
		switch v.(type) {
		case map[string]interface{}, []interface{}, map[interface{}]interface{}:
			if err := flatten(false, flatMap, v, newKey); err != nil {
				return err
			}
		default:
			flatMap[newKey] = v.(string)
		}

		return nil
	}

	switch nested.(type) {
	case map[string]interface{}:
		for k, v := range nested.(map[string]interface{}) {
			newKey := enkey(top, prefix, k)
			assign(newKey, v)
		}
	case map[interface{}]interface{}:
		for k, v := range nested.(map[interface{}]interface{}) {
			newKey := enkey(top, prefix, k.(string))
			assign(newKey, v)
		}
	case []interface{}:
		for i, v := range nested.([]interface{}) {
			newKey := enkey(top, prefix, strconv.Itoa(i))
			assign(newKey, v)
		}
	}

	return nil
}

func enkey(top bool, prefix, subkey string) string {
	key := prefix

	if top {
		key += subkey
	} else {
		key += "." + subkey
	}
	return key
}
