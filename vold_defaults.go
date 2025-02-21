package twrp

import (
	"android/soong/android"
	"android/soong/cc"
)

func globalFlags(ctx android.BaseContext) []string {
	var cflags []string

	if getMakeVars(ctx, "TW_USE_FSCRYPT_POLICY") == "1" {
		cflags = append(cflags, "-DUSE_FSCRYPT_POLICY_V1")
	} else {
		cflags = append(cflags, "-DUSE_FSCRYPT_POLICY_V2")
	}
	return cflags
}


func libVoldDefaults(ctx android.LoadHookContext) {
	type props struct {
		Target struct {
			Android struct {
				Cflags  []string
				Enabled *bool
			}
		}
		Cflags       []string
	}

	p := &props{}
	p.Cflags = globalFlags(ctx)
	ctx.AppendProperties(p)
}

func init() {
	android.RegisterModuleType("vold_defaults", libVoldDefaultsFactory)
}

func libVoldDefaultsFactory() android.Module {
	module := cc.DefaultsFactory()
	android.AddLoadHook(module, libVoldDefaults)

	return module
}
