# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2007 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

# Escaping
# xmlEncodeEntitiesReentrant(), encodeEntitiesReentrant()
# xmlNewTextChild()
# stringDecodeEntities

__all__ = [
    'string_to_xmlnode',
    'string_to_cdata_xmlnode',

    'validate_database_doc',
    'boolean',
    'xml_attributes',
    'xml_attribute_dict',
    'xml_child_elements_iter',
    'xml_child_elements',
    'xml_get_child_element_by_name',
    'xml_get_child_elements_by_name',
    'xml_child_element_names',
    'xml_has_child_elements',

    'XmlSerialize',
]

import sys
from types import *
import libxml2

from setroubleshoot.log import *
from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.util import *

#------------------------------------------------------------------------

i18n_encoding = get_config('general', 'i18n_encoding')

#------------------------------------------------------------------------

def validate_database_doc(doc):
    if doc is None:
        log_database.warning("validate_database_doc: doc is empty, validate fails")
        return False
    root_node = doc.getRootElement()
    if root_node is None:
        log_database.warning("validate_database_doc: root is empty, validate fails")
        return False
    version = root_node.prop('version')
    if version is None:
        log_database.warning("validate_database_doc: version is empty, validate fails")
        return False
    else:
        return database_version_compatible(version)

def boolean(value):
    'convert value to bool'
    if type(value) == BooleanType:
        return value
    elif type(value == StringType):
        value = value.lower()
        if value in ('t', 'true', '1'):
            return True
        elif value in ('f', 'false', '0'):
            return False
        else:
            raise ValueError("cannot convert (%s) to boolean" % value)
    elif type(value == IntType):
        return bool(value)
    else:
        raise ValueError("cannot convert (%s) to boolean" % value)


def string_to_xmlnode(doc, value):
    return libxml2.newText(str(value))

def string_to_cdata_xmlnode(doc, value):
    return doc.newCDataBlock(value, len(value))
    
# newChild() content is a string, which will be added as children

# addChild() adds xmlNode

#    newChild(None, name, stringGetNodeList(value))
# newTextChild --> newDocRawNode --> newDocNode;newDocText --> newText --> strdup(content)
# newChild --> newDocNode --> newNode;stringGetNodeList(content) # note: this inserts entity nodes if content contains &;

# xmlEncodeEntitiesReentrant called from xmlNodeListGetString
# xmlEncodeSpecialChars called from xmlNodeListGetRawString 
#------------------------------------------------------------------------

def xml_attributes(node):
    prop = node.get_properties()
    while prop:
        yield prop.get_name(), prop.get_content()
        prop = prop.get_next()


def xml_attribute_dict(node):
    props = {}
    for name, value in xml_attributes(node):
        props[name] = value
    return props

def xml_child_elements_iter(node):
    child = node.get_children()
    while child:
        if child.get_type() == 'element':
            yield child
        child = child.get_next()

def xml_get_child_element_by_name(node, name):
    child = node.get_children()
    while child:
        if child.get_type() == 'element':
            if child.get_name() == name: return child
        child = child.get_next()
    return None

def xml_get_child_elements_by_name(node, name):
    elements = []
    child = node.get_children()
    while child:
        if child.get_type() == 'element':
            if child.get_name() == name: elements.append(child)
        child = child.get_next()
    return elements

def xml_child_elements(node):
    return list(xml_child_elements_iter(node))

def xml_child_element_names(node):
    return [e.get_name() for e in xml_child_elements_iter(node)]

def xml_has_child_elements(node):
    child = node.get_children()
    while child:
        if child.get_type() == 'element':
            return True
        child = child.get_next()
    return False

#------------------------------------------------------------------------

class XmlSerializeMetaData(type):
    def __new__(cls, classname, bases, classdict):
        #print "new: cls=%s, name=%s bases=%s dict=%s" % (cls, classname, bases, classdict)

        if classname == 'XmlSerialize':
            return type.__new__(cls, classname, bases, classdict)

        normal_init = classdict.get('__init__')
        xml_init = classdict.get('init_from_xml_node', None)
        _init_postprocess = classdict.get('_init_postprocess', None)
        if xml_init is None:
            for base_cls in bases:
                #print "searching %s" % base_cls
                xml_init = base_cls.__dict__.get('init_from_xml_node', None)
                if xml_init is not None:
                    #print "found in %s" % base_cls
                    break
        else:
            pass
            #print "found in class %s" % classname


        def wrapped_init(*args, **kwds):
            if len(args) == 2 and isinstance(args[1], libxml2.xmlNode):
                xml_init(*args, **kwds)
                if _init_postprocess is not None:
                    _init_postprocess(args[0])
            else:
                normal_init(*args, **kwds)

        classdict['__init__'] = wrapped_init
        return type.__new__(cls, classname, bases, classdict)

    def __init__(cls, classname, bases, classdict):
        #print "init: cls=%s, name=%s bases=%s dict=%s" % (cls, classname, bases, classdict)
        super(XmlSerializeMetaData, cls).__init__(classname, bases, classdict)

        xml_info = classdict.get('_xml_info')
        if not xml_info: return
        if xml_info == 'unstructured':
            cls._unstructured = True
        else:
            cls._unstructured = False
            cls._elements = [x for x in xml_info.keys() if xml_info[x]['XMLForm'] == 'element']
            cls._attributes = [x for x in xml_info.keys() if xml_info[x]['XMLForm'] == 'attribute']
            cls._names = cls._elements + cls._attributes

            cls._elements.sort()
            cls._attributes.sort()
            cls._names.sort()

class XmlSerialize(object):
    __metaclass__ = XmlSerializeMetaData

    def __init__(self):
        self._init_defaults()

    def __str__(self):
        return self.get_xml_text_doc()

    def _init_defaults(self):
        # Initialize each known class variable to avoid KeyError on access
        if self._xml_info == 'unstructured': return
        for name in self._names:
            name_info = self._xml_info[name]
            default = name_info.get('default', None)
            if default is not None:
                setattr(self, name, default())
            else:
                if name_info.get('list'):
                    setattr(self, name, [])
                else:
                    setattr(self, name, None)

    def get_elements_and_attributes(self):
        if self._unstructured:
            elements = [x for x in self.__dict__.keys() if not x.startswith('_')]
            attributes = []
        else:
            elements   = self._elements
            attributes = self._attributes
        return(elements, attributes)


    def get_xml_doc(self, obj_name=None):
        doc = libxml2.newDoc("1.0")
        root = self.get_xml_nodes(doc, obj_name)
        doc.setRootElement(root)
        return doc

    def get_xml_text_doc(self, obj_name=None):
        doc = text_doc = None
        try:
            doc = self.get_xml_doc(obj_name)
            text_doc = doc.serialize(encoding=i18n_encoding, format=1)
        finally:
            if doc is not None:
                doc.freeDoc()
        return text_doc

    def read_xml(self, buf, obj_name=None):
        doc = None
        try:
            try:
                doc = libxml2.parseDoc(buf.strip())
                root_node = doc.getRootElement()
                self.init_from_xml_node(doc, obj_name)
            except libxml2.parserError, e:
                log_xml.error("read_xml() libxml2.parserError: %s", e)
                return
        finally:
            if doc is not None:
                doc.freeDoc()

    def read_xml_file(self, xmlfile, obj_name=None, validate_doc=None):
        doc = None
        try:
            try:
                doc = libxml2.parseFile(xmlfile)
                if validate_doc:
                    if not validate_doc(doc): return False
                self.init_from_xml_node(doc, obj_name)
            except libxml2.parserError, e:
                log_xml.error("read_xml_file() libxml2.parserError: %s", e)
                return False
            except Exception, e:
                log_xml.error("read_xml_file() error: %s", e)
                return False
        finally:
            if doc is not None:
                doc.freeDoc()
        return True

    def write_xml(self, obj_name=None, f = None):
        try:
            need_to_close = False
            if f is None:
                f = sys.stdout
            elif type(f) is StringType:
                f = open(f, "w")
                need_to_close = True
            elif type(f) is FileType:
                pass
            else:
                raise ValueError("bad file parameter %s" % f)

            f.write(self.get_xml_text_doc(obj_name))
            if need_to_close:
                f.close()
        except Exception, e:
            log_xml.error("could not write %s: %s", f, e)

    def get_xml_nodes(self, doc, obj_name=None):
        elements, attributes = self.get_elements_and_attributes()
        if obj_name is None:
            obj_name = self.__class__.__name__
        root = libxml2.newNode(obj_name)

        for name in attributes:
            name_info = self._xml_info[name]
            typecast = name_info.get('export_typecast', str)
            value = getattr(self, name)
            if value is not None:
                root.setProp(name, typecast(value))

        for name in elements:
            try:
                if self._xml_info == 'unstructured':
                    typecast = string_to_xmlnode
                    list_item_name = None
                else:
                    name_info = self._xml_info[name]
                    typecast = name_info.get('export_typecast', string_to_xmlnode)
                    list_item_name = name_info.get('list')

                value = getattr(self, name)
                if value is None or isinstance(value, list) and len(value) == 0: continue

                if list_item_name:
                    # Element is list container, iterate over list items
                    element_node = libxml2.newNode(name)
                    root.addChild(element_node)
                    for item in value:
                        if isinstance(item, XmlSerialize):
                            child = item.get_xml_nodes(doc, list_item_name)
                            element_node.addChild(child)
                        else:
                            list_item_node = libxml2.newNode(list_item_name)
                            element_node.addChild(list_item_node)
                            child = typecast(doc, item)
                            list_item_node.addChild(child)
                else:
                    # Element is scalar
                    if isinstance(value, XmlSerialize):
                        child = value.get_xml_nodes(doc, name)
                        root.addChild(child)
                    else:
                        element_node = libxml2.newNode(name)
                        root.addChild(element_node)
                        child = typecast(doc, value)
                        element_node.addChild(child)
            except Exception, e:
                log_xml.exception("%s.%s value=%s", self.__class__.__name__, name, value)

        return root

    def init_from_xml_node(self, xml_node, obj_name=None):
        elements, attributes = self.get_elements_and_attributes()
        self._init_defaults()

        if debug:
            #log_xml.debug("init_from_xml_node(): obj_name='%s' xml_node=%s", obj_name, repr(xml_node))
            pass

        if obj_name is None:
            root = xml_node
        else:
            root = xml_get_child_element_by_name(xml_node, obj_name)
            if root is None:
                raise KeyError("xml child element (%s) not found in node %s" % (obj_name, xml_node.get_name()))

        if debug:
            #log_xml.debug("doc=%s\n%s\nxml_node=%s\n%s", repr(doc), doc, repr(xml_node), xml_node)
            pass

        # Read the attributes in the xml node Cast the attribute value
        # to a Python type and store coerced value in the Python
        # object (self) which can then be accessed by "name"

        for name, value in xml_attributes(root):
            if name not in attributes:
                log_xml.warning("unknown attribute (%s) found in xml element (%s)", name, root.get_name())
                continue
            name_info = self._xml_info[name]
            typecast = name_info.get('import_typecast', str)
            if isinstance(typecast, type) and issubclass(typecast, XmlSerialize):
                raise ValueError("Illegal use of substructure in attribute (%s)" % name)
            else:
                self.__setattr__(name, typecast(value))

        for element_node in xml_child_elements_iter(root):
            name = element_node.get_name()
            if self._unstructured:
                # Unstructured data, store the string content of each
                # element in the Python object (self) which can then
                # be accessed by "name"
                value = element_node.getContent()
                self.__setattr__(name, value)
            else:
                # Recursively read the contents of each element.  Casting to a
                # Python types along the recursion path and store the final
                # Python value in the Python object (self) which can then be
                # accessed by "name"
                if name not in elements:
                    log_xml.warning("unknown element (%s) found in xml element (%s)", name, root.get_name())
                    continue
                name_info = self._xml_info[name]
                typecast =  name_info.get('import_typecast', str)
                # Does this node have substructure?
                list_item_name = name_info.get('list')
                if list_item_name:
                    # Element is a list, recursively iterate over the elements children, e.g. list elements
                    attr = getattr(self, name, [])
                    list_nodes = xml_get_child_elements_by_name(element_node, list_item_name)
                    if isinstance(typecast, type) and issubclass(typecast, XmlSerialize):
                        for list_node in list_nodes:
                            attr.append(typecast(list_node))
                    else:
                        for list_node in list_nodes:
                            attr.append(typecast(list_node.getContent()))
                else:
                    if isinstance(typecast, type) and issubclass(typecast, XmlSerialize):
                        self.__setattr__(name, typecast(element_node))
                    else:
                        value = element_node.getContent()
                        self.__setattr__(name, typecast(value))



