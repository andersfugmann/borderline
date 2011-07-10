## Generic functions for ocaml makefile
## This makefile compiles ocaml binaries using ocamlfind.
## Dependancies are generated by looking at dependancy files generated by 
## ocamldep.

# TODO:
# Try passing descendands (-r) to ocamlfind

vpath %.cmo $(BUILD_DIR)
vpath %.cmi $(BUILD_DIR)
vpath %.cmx $(BUILD_DIR)
vpath %.o $(BUILD_DIR)
vpath gendep $(BUILD_DIR)
vpath $(BINARIES) $(BUILD_DIR)

SOURCES := $(sort $(filter %.mli %.ml, $(SOURCES)) $(MLLS:.mll=.ml) $(MLYS:.mly=.mli) $(MLYS:.mly=.ml))  

#MAKEFLAGS = --no-print-directory
SHELL := bash
BINARY_DEPS := $(addprefix $(BUILD_DIR)/, $(addsuffix .d, $(BINARIES)))
GRAMMER_FILES = $(LEX_FILES:.mll=.ml) $(YACC_FILES:.mly=.mli) $(YACC_FILES:.mly=.ml)  

OCAMLFIND_ARGS = $(addprefix -I $(BUILD_DIR)/,$(INCLUDE)) -package "$(PACKAGES)" 
ifdef OPTIMIZED
COMPILE_SUFFIX = .cmx
LD=ocamlopt
else
COMPILE_SUFFIX =.cmo
LD=ocamlc
endif 

ifneq ($(MAKECMDGOALS),clean)
$(foreach dir,$(INCLUDE),$(shell mkdir -p $(BUILD_DIR)/$(dir)))
-include $(DEPENDS) $(BINARY_DEPS)
endif

.PHONY: install clean doc force

force:

#.DELETE_ON_ERROR: $(DEPENDS) $(BINARY_DEPENDS) $(BINARIES)
$(BINARY_DEPS): $(BUILD_DIR)/%.d: $(BUILD_DIR)/%.ml.d gendep $(GRAMMER_FILES)
	@echo "Depend:  " $(subst $(BUILD_DIR)/,,$@)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@$(BUILD_DIR)/gendep -prefix $(BUILD_DIR) -suffix $(COMPILE_SUFFIX) $(subst $(BUILD_DIR)/,,$(@:.d=)) > $@

$(BUILD_DIR)/%.d: %
	@echo "Depend:  " $(subst $(BUILD_DIR)/,,$@)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@ocamlfind ocamldep $(addprefix -I ,$(INCLUDE) $(dir $<)) -package "$(PACKAGES)" $< > $@

gendep.cmo: OCFLAGS += -rectypes
%.cmo: %.ml 
	@echo "Compile: " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind ocamlc -c $(OCFLAGS) $(OCAMLFIND_ARGS) $< -o $(BUILD_DIR)/$@

gendep.cmx: OCFLAGS += -rectypes
%.cmx: %.ml
	@echo "Compile: " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind ocamlopt -c $(OCFLAGS) $(OCAMLFIND_ARGS) $< -o $(BUILD_DIR)/$@

%.cmi: %.mli
	@echo "Compile: " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind ocamlc -c $(OCFLAGS) $(OCAMLFIND_ARGS) $< -o $(BUILD_DIR)/$@

%.ml: %.mll
	@echo "Lexer:   " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamllex -q $<

%.ml %.mli: %.mly
	@echo "Parser:  " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlyacc $<

%.o: %.c
	@echo "Compile: " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind ocamlc -c $(OCFLAGS) -cclib "$(addprefix -l, $(CLIBS))" -ccopt "$(CFLAGS)" $< 
	@mv $(notdir $@) $(BUILD_DIR)/$@

gendep: gendep.cmx
	@echo "Link:    " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind ocamlopt $(OCFLAGS) -package str -rectypes $(BUILD_DIR)/gendep.cmx -linkpkg -o $(BUILD_DIR)/$@

$(BINARIES): %: $(OBJECTS)
	@echo "Link:    " $(subst $(BUILD_DIR),,$@)
	@[ -d $(BUILD_DIR)/$(dir $@) ] || mkdir -p $(BUILD_DIR)/$(dir $@)
	@ocamlfind $(LD) $(OCFLAGS) $(OCAMLFIND_ARGS) -cclib "$(addprefix -l , $(CLIBS))" -ccopt "$(CFLAGS)" -linkpkg -o $(BUILD_DIR)/$@ $(addprefix $(BUILD_DIR)/, $(subst $(BUILD_DIR)/,,$+))
#(OBJECTS) $(addprefix $(BUILD_DIR)/, $($@_objs))


install:: $(BINARIES)
	@echo "Install: " $(notdir $(BINARIES))
	@[ -d $(BIN_DIR) ] || mkdir $(BIN_DIR)
	@for f in $(addprefix $(BUILD_DIR)/, $(BINARIES)); do t=$(BIN_DIR)/$$(basename $$f); [ $$f -ot $$t ] || cp -f $$f $$t; done

clean::
	@echo "Clean."
	@find . -name \*.d -o -name \*.cm? -o -name \*.o | xargs $(RM) 
	@$(RM) -r $(BUILD_DIR) $(BIN_DIR) $(DOC_DIR) $(GRAMMER_FILES)

doc: $(subst .ml,.cmo,$(filter %.ml, $(SOURCES))) $(subst .mli,.cmi,$(filter %.mli, $(SOURCES))) 
	@echo "Documentation"
	@[ -d $(DOC_DIR) ] || mkdir $(DOC_DIR)
	@ocamlfind ocamldoc -html -d $(DOC_DIR) $(addprefix -I $(BUILD_DIR)/,$(INCLUDE)) -package "$(PACKAGES)" $(SOURCES)
