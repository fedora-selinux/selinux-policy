// Author: Thomas Liu <tliu@redhat.com>

#include "sesearch.c"

static int Dict_ContainsInt(PyObject *dict, const char *key){
    PyObject *item = PyDict_GetItemString(dict, key);
    if (item)
        return PyInt_AsLong(item);
    return false;
}

static const char *Dict_ContainsString(PyObject *dict, const char *key){
    PyObject *item = PyDict_GetItemString(dict, key);
    if (item)
        return PyString_AsString(item);
    return NULL;
}

PyObject *wrap_sesearch(PyObject *self, PyObject *args){
    PyObject *dict;
    if (!PyArg_ParseTuple(args, "O", &dict))
        return NULL;
    int allow = Dict_ContainsInt(dict, "allow");
    int neverallow = Dict_ContainsInt(dict, "neverallow");
    int auditallow = Dict_ContainsInt(dict, "auditallow");
    int dontaudit = Dict_ContainsInt(dict, "dontaudit"); 
   
    const char *src_name = Dict_ContainsString(dict, "scontext");
    const char *tgt_name = Dict_ContainsString(dict, "tcontext");
    const char *class_name = Dict_ContainsString(dict, "class");
    const char *permlist = Dict_ContainsString(dict, "permlist");
    
    return Py_BuildValue("O",sesearch(allow, neverallow, auditallow, dontaudit, src_name, tgt_name, class_name, permlist));

}

static PyMethodDef methods[] = {
    {"search", (PyCFunction) wrap_sesearch, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

void init_sesearch(){
    PyObject *m;
    m = Py_InitModule("_sesearch", methods);
}
