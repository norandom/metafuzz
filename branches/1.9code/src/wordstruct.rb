require 'binstruct'
module WordStructures

    class StructuredStorageHeader < BinStruct
        hexstring :sig, 8*8,	"Signature"
        hexstring :classid, 16*8, "CLSID"
        unsigned :minorver, 2*8, "Minor Version"
        unsigned :majorver, 2*8, "Major Version"
        hexstring :byteorder, 2*8, "Byte Order"
        unsigned :sectorshift, 2*8, "Sector Shift (size)"
        unsigned :minisectorshift, 2*8, "Mini Sector Shift (size)"
        unsigned :res, 2*8, "Reserved"
        unsigned :res1, 4*8, "Reserved1"
        unsigned :res2, 4*8, "Reserved2"
        unsigned :sectcount, 4*8, "Number of Sects"
        unsigned :firstsect, 4*8, "First Sect Offset"
        unsigned :transactionsig, 4*8, "Transaction Signature"
        unsigned :minisectcutoff, 4*8, "Mini Stream Max Size"
        unsigned :minifatstart, 4*8, "First Sect in Mini FAT chain"
        unsigned :minifatcount, 4*8, "Number of Mini FAT Sects"
        unsigned :difstart, 4*8, "First Sect in DIF chain"
        unsigned :difcount, 4*8, "Number of DIF Sects"
        hexstring :fat109, 436*8, "First 109 Sects"

        default_value :sig, "d0 cf 11 e0 a1 b1 1a e1"
        default_value :minorver, 33
        default_value :majorver, 3
        default_value :byteorder, "ff fe"
        default_value :sectorshift, 9
        default_value :minisectorshift, 6
        default_value :minisectcutoff, 4096
        endianness "intel"
    end

    class WordFIB < BinStruct

        unsigned :wIdent, 16, "0 Magic number"
        unsigned :nFib, 16, "2 FIB version written. This will be >= 101 for all Word 6.0 for[...]"
        unsigned :nProduct, 16, "4 Product version written by"
        unsigned :Lid, 16, "6 Language stamp --localized version In pre-WinWord 2.0 files t[...]"
        unsigned :pnNext, 16, ""
        unsigned :fDot, 1, "10 Set if this document is a template"
        unsigned :fGlsy, 1, "Set if this document is a glossary"
        unsigned :fComplex, 1, "When 1, file is in complex, fast-saved format."
        unsigned :fHasPic, 1, "Set if file contains 1 or more pictures"
        unsigned :cQuickSaves, 4, "Count of times file was quick saved"
        unsigned :fEncrypted, 1, "Set if file is encrypted"
        unsigned :fWhichTblStm, 1, "When 0, this fib refers to the table stream named ?0Table?, whe[...]"
        unsigned :fReadOnlyRecommended, 1, "Set when user has recommended that file be read read-only"
        unsigned :fWriteReservation, 1, "Set when file owner has made the file write reserved"
        unsigned :fExtChar, 1, "Set when using extended character set in file"
        unsigned :fLoadOverride, 1, "REVIEW"
        unsigned :fFarEast, 1, "REVIEW"
        unsigned :fCrypto, 1, "REVIEW"
        unsigned :nFibBack, 16, "12 This file format is compatible with readers that understand [...]"
        unsigned :lKey, 32, ""
        unsigned :Envr, 8, "18 Environment in which file was created 0 created by Word for [...]"
        unsigned :fMac, 1, "19 When 1, this file was last saved in the Macintosh environment"
        unsigned :fEmptySpecial, 1, ""
        unsigned :fLoadOverridePage, 1, ""
        unsigned :fFutureSavedUndo, 1, ""
        unsigned :fWord97Saved, 1, ""
        unsigned :fSpare0, 3, ""
        unsigned :Chs, 16, "20 Default extended character set id for text in document strea[...]"
        hexstring :chsTables, 16, "22 Default extended character set id for text in internal data [...]"
        unsigned :fcMin, 32, "24 File offset of first character of text. In non-complex files[...]"
        unsigned :fcMac, 32, "28 File offset of last character of text in document text strea[...]"
        unsigned :Csw, 16, "32 Count of fields in the array of ?shorts?"
        unsigned :wMagicCreated, 16, ""
        unsigned :wMagicRevised, 16, ""
        unsigned :wMagicCreatedPrivate, 16, ""
        unsigned :wMagicRevisedPrivate, 16, ""
        unsigned :pnFbpChpFirst_W6, 16, "42 Not used"
        unsigned :pnChpFirst_W6, 16, "44 Not used"
        unsigned :cpnBteChp_W6, 16, "46 Not used"
        unsigned :pnFbpPapFirst_W6, 16, "48 Not used"
        unsigned :pnPapFirst_W6, 16, "50 Not used"
        unsigned :cpnBtePap_W6, 16, "52 Not used"
        unsigned :pnFbpLvcFirst_W6, 16, "54 Not used"
        unsigned :pnLvcFirst_W6, 16, "56 Not used"
        unsigned :cpnBteLvc_W6, 16, "58 Not used"
        unsigned :lidFE, 16, "60 Language id if document was written by East Asian version of[...]"
        unsigned :Clw, 16, "62 Number of fields in the array of longs"
        unsigned :cbMac, 32, "64 File offset of last byte written to file + 1"
        unsigned :lProductCreated, 32, ""
        unsigned :lProductRevised, 32, "72 Decimal"
        unsigned :ccpText, 32, "76 Length of main document text stream 1"
        unsigned :ccpFtn, 32, "80 Length of footnote subdocument text stream"
        unsigned :ccpHdd, 32, "84 Length of header subdocument text stream"
        unsigned :ccpMcr, 32, "88 Length of macro subdocument text stream, which should now al[...]"
        unsigned :ccpAtn, 32, "92 Length of annotation subdocument text stream"
        unsigned :ccpEdn, 32, "96 Length of endnote subdocument text stream"
        unsigned :ccpTxbx, 32, "100 Length of textbox subdocument text stream"
        unsigned :ccpHdrTxbx, 32, "104 Length of header textbox subdocument text stream"
        unsigned :pnFbpChpFirst, 32, "108 When there was insufficient memory for Word to expand the p[...]"
        unsigned :pnChpFirst, 32, "112 The page number of the lowest numbered page in the document[...]"
        unsigned :cpnBteChp, 32, "116 Count of CHPX FKPs recorded in file. In non-complex files i[...]"
        unsigned :pnFbpPapFirst, 32, "120 When there was insufficient memory for Word to expand the p[...]"
        unsigned :pnPapFirst, 32, "124 The page number of the lowest numbered page in the document[...]"
        unsigned :cpnBtePap, 32, "128 Count of PAPX FKPs recorded in file. In non-complex files i[...]"
        unsigned :pnFbpLvcFirst, 32, "132 When there was insufficient memory for Word to expand the p[...]"
        unsigned :pnLvcFirst, 32, "136 The page number of the lowest numbered page in the document[...]"
        unsigned :cpnBteLvc, 32, "140 Count of LVC FKPs recorded in file. In non-complex files if[...]"
        unsigned :fcIslandFirst, 32, ""
        unsigned :fcIslandLim, 32, ""
        unsigned :Cfclcb, 16, "152 Number of fields in the array of FC/LCB pairs"
        unsigned :fcStshfOrig, 32, "154 File offset of original allocation for STSH in table stream[...]"
        unsigned :lcbStshfOrig, 32, "158 Count of bytes of original STSH allocation"
        unsigned :fcStshf, 32, "162 Offset of STSH in table stream"
        unsigned :lcbStshf, 32, "166 Count of bytes of current STSH allocation"
        unsigned :fcPlcffndRef, 32, "170 Offset in table stream of footnote reference PLCF of FRD st[...]"
        unsigned :lcbPlcffndRef, 32, "174 Count of bytes of footnote reference PLC== 0 if no footnote[...]"
        unsigned :fcPlcffndTxt, 32, "178 Offset in table stream of footnote text PLC. CPs in PLC are[...]"
        unsigned :lcbPlcffndTxt, 32, "182 Count of bytes of footnote text PLC. == 0 if no footnotes d[...]"
        unsigned :fcPlcfandRef, 32, "186 Offset in table stream of annotation reference ATRDPre10 PL[...]"
        unsigned :lcbPlcfandRef, 32, "190 Count of bytes of annotation reference PLC"
        unsigned :fcPlcfandTxt, 32, "194 Offset in table stream of annotation text PLC. The CPs reco[...]"
        unsigned :lcbPlcfandTxt, 32, "198 Count of bytes of the annotation text PLC"
        unsigned :fcPlcfsed, 32, "202 Offset in table stream of section descriptor SED PLC. CPs i[...]"
        unsigned :lcbPlcfsed, 32, "206 Count of bytes of section descriptor PLC"
        unsigned :fcPlcpad, 32, "210 No longer used"
        unsigned :lcbPlcpad, 32, "214 No longer used"
        unsigned :fcPlcfphe, 32, "218 Offset in table stream of PHE PLC of paragraph heights. CPs[...]"
        unsigned :lcbPlcfphe, 32, "222 Count of bytes of paragraph height PLC. ==0 when file is no[...]"
        unsigned :fcSttbfglsy, 32, "226 Offset in table stream of glossary string table. This table[...]"
        unsigned :lcbSttbfglsy, 32, "230 Count of bytes of glossary string table. == 0 for non-gloss[...]"
        unsigned :fcPlcfglsy, 32, "234 Offset in table stream of glossary PLC. CPs in PLC are rela[...]"
        unsigned :lcbPlcfglsy, 32, "238 Count of bytes of glossary PLC. == 0 for non-glossary docum[...]"
        unsigned :fcPlcfhdd, 32, "242 Byte offset in table stream of header HDD PLC. CPs are rela[...]"
        unsigned :lcbPlcfhdd, 32, "246 Count of bytes of header PLC. == 0 if document contains no [...]"
        unsigned :fcPlcfbteChpx, 32, "250 Offset in table stream of character property bin table.PLC.[...]"
        unsigned :lcbPlcfbteChpx, 32, "254 Count of bytes of character property bin table PLC"
        unsigned :fcPlcfbtePapx, 32, "258 Offset in table stream of paragraph property bin table.PLC.[...]"
        unsigned :lcbPlcfbtePapx, 32, "262 Count of bytes of paragraph property bin table PLC"
        unsigned :fcPlcfsea, 32, "266 Offset in table stream of PLC reserved for private use. The[...]"
        unsigned :lcbPlcfsea, 32, "270 Count of bytes of private use PLC"
        unsigned :fcSttbfffn, 32, "274 Offset in table stream of font information STTBF. The sttbf[...]"
        unsigned :lcbSttbfffn, 32, "278 Count of bytes in sttbfffn"
        unsigned :fcPlcffldMom, 32, "282 Offset in table stream to the FLD PLC of field positions in[...]"
        unsigned :lcbPlcffldMom, 32, "286 Count of bytes in plcffldMom"
        unsigned :fcPlcffldHdr, 32, "290 Offset in table stream to the FLD PLC of field positions in[...]"
        unsigned :lcbPlcffldHdr, 32, "294 Count of bytes in plcffldHdr"
        unsigned :fcPlcffldFtn, 32, "298 Offset in table stream to the FLD PLC of field positions in[...]"
        unsigned :lcbPlcffldFtn, 32, "302 Count of bytes in plcffldFtn"
        unsigned :fcPlcffldAtn, 32, "306 Offset in table stream to the FLD PLC of field positions in[...]"
        unsigned :lcbPlcffldAtn, 32, "310 Count of bytes in plcffldAtn"
        unsigned :fcPlcffldMcr, 32, "314 No longer used"
        unsigned :lcbPlcffldMcr, 32, "318 No longer used"
        unsigned :fcSttbfbkmk, 32, "322 Offset in table stream of the STTBF that records bookmark n[...]"
        unsigned :lcbSttbfbkmk, 32, "326 Count of bytes in Sttbfbkmk"
        unsigned :fcPlcfbkf, 32, "330 Offset in table stream of the PLCF that records the beginni[...]"
        unsigned :lcbPlcfbkf, 32, "334 Count of bytes in Plcfbkf"
        unsigned :fcPlcfbkl, 32, "338 Offset in table stream of the PLCF that records the ending [...]"
        unsigned :lcbPlcfbkl, 32, "342 Count of bytes in Plcfbkl"
        unsigned :fcCmds, 32, "346 Offset in table stream of the macro commands. These command[...]"
        unsigned :lcbCmds, 32, "350 Count of bytes of the data above."
        unsigned :fcPlcmcr, 32, "354 No longer used"
        unsigned :lcbPlcmcr, 32, "358 No longer used"
        unsigned :fcSttbfmcr, 32, "362 No longer used"
        unsigned :lcbSttbfmcr, 32, "366 No longer used"
        unsigned :fcPrDrvr, 32, "370 Offset in table stream of the printer driver information (n[...]"
        unsigned :lcbPrDrvr, 32, "374 Count of bytes of the printer driver information (names of [...]"
        unsigned :fcPrEnvPort, 32, "378 Offset in table stream of the print environment in portrait[...]"
        unsigned :lcbPrEnvPort, 32, "382 Count of bytes of the print environment in portrait mode"
        unsigned :fcPrEnvLand, 32, "386 Offset in table stream of the print environment in landscap[...]"
        unsigned :lcbPrEnvLand, 32, "390 Count of bytes of the print environment in landscape mode"
        unsigned :fcWss, 32, "394 Offset in table stream of Window Save State data structure.[...]"
        unsigned :lcbWss, 32, "398 Count of bytes of WSS. ==0 if unable to store the window st[...]"
        unsigned :fcDop, 32, "402 Offset in table stream of document property data structure"
        unsigned :lcbDop, 32, "406 Count of bytes of document properties"
        unsigned :fcSttbfAssoc, 32, "410 Offset in table stream of STTBF of associated strings. The [...]"
        unsigned :lcbSttbfAssoc, 32, "414 Count of bytes in SttbfAssoc"
        unsigned :fcClx, 32, "418 Offset in table stream of beginning of information for comp[...]"
        unsigned :lcbClx, 32, "422 Count of bytes of complex file information == 0 if file is [...]"
        unsigned :fcPlcfpgdFtn, 32, "426 Not used"
        unsigned :lcbPlcfpgdFtn, 32, "430 Not used"
        unsigned :fcAutosaveSource, 32, "434 Offset in table stream of the name of the original file. fc[...]"
        unsigned :lcbAutosaveSource, 32, "438 Count of bytes of the name of the original file."
        unsigned :fcGrpXstAtnOwners, 32, "442 Offset in table stream of group of strings recording the na[...]"
        unsigned :lcbGrpXstAtnOwners, 32, "446 Count of bytes of the group of strings"
        unsigned :fcSttbfAtnbkmk, 32, "450 Offset in table stream of the sttbf that records names of b[...]"
        unsigned :lcbSttbfAtnbkmk, 32, "454 Length in bytes of the sttbf that records names of bookmark[...]"
        unsigned :fcPlcdoaMom, 32, "458 No longer used"
        unsigned :lcbPlcdoaMom, 32, "462 No longer used"
        unsigned :fcPlcdoaHdr, 32, "466 No longer used"
        unsigned :lcbPlcdoaHdr, 32, "470 No longer used"
        unsigned :fcPlcspaMom, 32, "474 Offset in table stream of the FSPA PLC for main document. =[...]"
        unsigned :lcbPlcspaMom, 32, "478 Length in bytes of the FSPA PLC of the main document"
        unsigned :fcPlcspaHdr, 32, "482 Offset in table stream of the FSPA PLC for header document.[...]"
        unsigned :lcbPlcspaHdr, 32, "486 Length in bytes of the FSPA PLC of the header document."
        unsigned :fcPlcfAtnbkf, 32, "490 Offset in table stream of BKF (bookmark first) PLC of the a[...]"
        unsigned :lcbPlcfAtnbkf, 32, "494 Length in bytes of BKF (bookmark first) PLC of the annotati[...]"
        unsigned :fcPlcfAtnbkl, 32, "498 Offset in table stream of BKL (bookmark last) PLC of the an[...]"
        unsigned :lcbPlcfAtnbkl, 32, "502 Length in bytes of PLC marking the CP limits of the annotat[...]"
        unsigned :fcPms, 32, "506 Offset in table stream of PMS (Print Merge State) informati[...]"
        unsigned :lcbPms, 32, "510 Length in bytes of PMS. ==0 if no current print merge state[...]"
        unsigned :fcFormFldSttbs, 32, "514 Offset in table stream of form field sttbf which contains s[...]"
        unsigned :lcbFormFldSttbs, 32, "518 Length in bytes of form field sttbf"
        unsigned :fcPlcfendRef, 32, "522 Offset in table stream of endnote reference PLCF of FRD str[...]"
        unsigned :lcbPlcfendRef, 32, "526 Count of bytes of the plcfendRef"
        unsigned :fcPlcfendTxt, 32, "530 Offset in table stream of plcfendRef which points to endnot[...]"
        unsigned :lcbPlcfendTxt, 32, "534 Count of bytes for the above data"
        unsigned :fcPlcffldEdn, 32, "538 Offset in table stream to FLD PLCF of field positions in th[...]"
        unsigned :lcbPlcffldEdn, 32, "542 Count of bytes for the above data"
        unsigned :fcPlcfpgdEdn, 32, "546 Not used"
        unsigned :lcbPlcfpgdEdn, 32, "550 Not used"
        unsigned :fcDggInfo, 32, "554 Offset in table stream of the Office Drawing object table d[...]"
        unsigned :lcbDggInfo, 32, "558 Length in bytes of the Office Drawing object table data"
        unsigned :fcSttbfRMark, 32, "562 Offset in table stream to STTBF that records the author abb[...]"
        unsigned :lcbSttbfRMark, 32, "566 Count of bytes for the above data"
        unsigned :fcSttbCaption, 32, "570 Offset in table stream to STTBF that records caption titles[...]"
        unsigned :lcbSttbCaption, 32, "574 Count of bytes for the above data"
        unsigned :fcSttbAutoCaption, 32, "578 Offset in table stream to the STTBF that records the object[...]"
        unsigned :lcbSttbAutoCaption, 32, "582 Count of bytes for the above data"
        unsigned :fcPlcfwkb, 32, "586 Offset in table stream to WKB PLCF that describes the bound[...]"
        unsigned :lcbPlcfwkb, 32, "590 Count of bytes for the above data"
        unsigned :fcPlcfspl, 32, "594 Offset in table stream of PLCF (of SPLS structures) that re[...]"
        unsigned :lcbPlcfspl, 32, "598 Count of bytes for the above data"
        unsigned :fcPlcftxbxTxt, 32, "602 Offset in table stream of PLCF that records the beginning C[...]"
        unsigned :lcbPlcftxbxTxt, 32, "606 Count of bytes for the above data"
        unsigned :fcPlcffldTxbx, 32, "610 Offset in table stream of the FLD PLCF that records field b[...]"
        unsigned :lcbPlcffldTxbx, 32, "614 Count of bytes for the above data"
        unsigned :fcPlcfhdrtxbxTxt, 32, "618 Offset in table stream of PLCF that records the beginning C[...]"
        unsigned :lcbPlcfhdrtxbxTxt, 32, "622 Count of bytes for the above data"
        unsigned :fcPlcffldHdrTxbx, 32, "626 Offset in table stream of the FLD PLCF that records field b[...]"
        unsigned :lcbPlcffldHdrTxbx, 32, "630 Count of bytes for the above data"
        unsigned :fcStwUser, 32, "634 Macro user storage"
        unsigned :lcbStwUser, 32, "638 Count of bytes for the above data"
        unsigned :fcSttbttmbd, 32, "642 Offset in table stream of embedded true type font data"
        unsigned :cbSttbttmbd, 32, "646 Count of bytes for the above data"
        unsigned :fcCookieData, 32, "650 NLCheck error handle will persist in file"
        unsigned :lcbCookieData, 32, "654 Count of bytes for the above data"
        unsigned :fcpgdMotherOldOld, 128, "658 Offsets in table stream of the PLF that records the page an[...]"
        unsigned :fcpgdFtnOldOld, 128, "674 Offsets in table stream of the PLF that records the page an[...]"
        unsigned :fcpgdEdnOldOld, 128, "690 Offsets in table stream of the PLF that records the page an[...]"
        unsigned :fcSttbfIntlFld, 32, "706 Offset in table stream of the STTBF containing field keywor[...]"
        unsigned :lcbSttbfIntlFld, 32, "710 Always 0 for nFib>=167"
        unsigned :fcRouteSlip, 32, "714 Offset in table stream of a mailer routing slip"
        unsigned :lcbRouteSlip, 32, "718 Count of bytes for the above data"
        unsigned :fcSttbSavedBy, 32, "722 Offset in table stream of STTBF recording the names of the [...]"
        unsigned :lcbSttbSavedBy, 32, "726 Count of bytes for the above data"
        unsigned :fcSttbFnm, 32, "730 Offset in table stream of STTBF recording filenames of docu[...]"
        unsigned :lcbSttbFnm, 32, "734 Count of bytes for the above data"
        unsigned :fcPlcfLst, 32, "738 Offset in the table stream of list format information"
        unsigned :lcbPlcfLst, 32, "742 Count of bytes for the above data"
        unsigned :fcPlfLfo, 32, "746 Offset in the table stream of list format override informat[...]"
        unsigned :lcbPlfLfo, 32, "750 Count of bytes for the above data"
        unsigned :fcPlcftxbxBkd, 32, "754 Offset in the table stream of the textbox break table (a PL[...]"
        unsigned :lcbPlcftxbxBkd, 32, "758 Count of bytes for the above data"
        unsigned :fcPlcftxbxHdrBkd, 32, "762 Offset in the table stream of the textbox break table (a PL[...]"
        unsigned :lcbPlcftxbxHdrBkd, 32, "766 Count of bytes for the above data"
        unsigned :fcDocUndoWord9, 32, "770 Offset in main stream of undocumented undo / versioning dat[...]"
        unsigned :lcbDocUndoWord9, 32, "774 Count of bytes for the above data"
        unsigned :fcRgbuse, 32, "778 Offset in main stream of undocumented undo / versioning data"
        unsigned :lcbRgbuse, 32, "782 Count of bytes for the above data"
        unsigned :fcUsp, 32, "786 Offset in main stream of undocumented undo / versioning data"
        unsigned :lcbUsp, 32, "790 Count of bytes for the above data"
        unsigned :fcUskf, 32, "794 Offset in table stream of undocumented undo / versioning da[...]"
        unsigned :lcbUskf, 32, "798 Count of bytes for the above data"
        unsigned :fcPlcupcRgbuse, 32, "802 Offset in table stream of undocumented undo / versioning da[...]"
        unsigned :lcbPlcupcRgbuse, 32, "806 Count of bytes for the above data"
        unsigned :fcPlcupcUsp, 32, "810 Offset in table stream of undocumented undo / versioning da[...]"
        unsigned :lcbPlcupcUsp, 32, "814 Count of bytes for the above data"
        unsigned :fcSttbGlsyStyle, 32, "818 Offset in table stream of string table of style names for g[...]"
        unsigned :lcbSttbGlsyStyle, 32, "822 Count of bytes for the above data"
        unsigned :fcPlgosl, 32, "826 Offset in table stream of undocumented grammar options PL"
        unsigned :lcbPlgosl, 32, "830 Count of bytes for the above data"
        unsigned :fcPlcocx, 32, "834 Offset in table stream of undocumented ocx data"
        unsigned :lcbPlcocx, 32, "838 Count of bytes for the above data"
        unsigned :fcPlcfbteLvc, 32, "842 Offset in table stream of character property bin table.PLC.[...]"
        unsigned :lcbPlcfbteLvc, 32, "846 Count of bytes for the above data"
        unsigned :dwLowDateTime, 32, ""
        unsigned :dwHighDateTime, 32, ""
        unsigned :fcPlcflvcPre10, 32, "858 Offset in table stream of LVC PLCF used pre Word10"
        unsigned :lcbPlcflvcPre10, 32, "862 Size of LVC PLCF, ==0 for non-complex files"
        unsigned :fcPlcasumy, 32, "866 Offset in table stream of autosummary ASUMY PLCF."
        unsigned :lcbPlcasumy, 32, "870 Count of bytes for the above data"
        unsigned :fcPlcfgram, 32, "874 Offset in table stream of PLCF (of SPLS structures) which r[...]"
        unsigned :lcbPlcfgram, 32, "878 Count of bytes for the above data"
        unsigned :fcSttbListNames, 32, "882 Offset in table stream of list names string table"
        unsigned :lcbSttbListNames, 32, "886 Count of bytes for the above data"
        unsigned :fcSttbfUssr, 32, "890 Offset in table stream of undocumented undo / versioning da[...]"
        unsigned :lcbSttbfUssr, 32, "894 Count of bytes for the above data"
        unsigned :fcPlcfTch, 32, "898 Offset in table stream of table chars This is an internal c[...]"
        unsigned :lcbPlcfTch, 32, "902 Count of bytes of the above data"
        unsigned :fcRmdfThreading, 32, "906 Offset in table stream of revision mark data This informati[...]"
        unsigned :lcbRmdfThreading, 32, "910 Count of bytes for the above data"
        unsigned :fcMid, 32, "914 Offset in table stream of Message ID (if any) This informat[...]"
        unsigned :lcbMid, 32, "918 Count of bytes for the above data"
        unsigned :fcSttbRgtplc, 32, "922 Offset in table stream of list gallery data (tplcs) This is[...]"
        unsigned :lcbSttbRgtplc, 32, "926 Count of bytes for the above data"
        unsigned :fcMsoEnvelope, 32, "930 Offset in table stream of persist the mail envelope This is[...]"
        unsigned :lcbMsoEnvelope, 32, "934 Count of bytes for the above data"
        unsigned :fcPlcflad, 32, "938 Offset in table stream of Language Auto Detect results This[...]"
        unsigned :lcbPlcflad, 32, "942 Count of bytes for the above data"
        unsigned :fcRgdofr, 32, "946 Document File Records (miscellaneous document data) This is[...]"
        unsigned :lcbRgdofr, 32, "950 Count of bytes for the above data"
        unsigned :fcPlcosl, 32, "954 Offset in table stream of NLCheck grammar option state per [...]"
        unsigned :lcbPlcosl, 32, "958 Count of bytes for the above data"
        unsigned :fcPlcfcookieOld, 32, "962 Offset in table stream of NLCheck error handle pre Word10 T[...]"
        unsigned :lcbPlcfcookieOld, 32, "966 Count of bytes for the above data"
        unsigned :fcpgdMotherOld, 128, "970 Main document repagination cache: used internally by Word T[...]"
        unsigned :fcpgdFtnOld, 128, "986 Footnotes repagination cache: used internally by Word This [...]"
        unsigned :fcpgdEdnOld, 128, "1002 Endnotes repagination cache: used internally by Word This [...]"
        unsigned :fcUnused, 32, "1018 Not used"
        unsigned :lcbUnused, 32, "1022 Not used"
        unsigned :fcPlcfpgp, 32, "1026 Offset in table stream of Paragraph Group Properties This [...]"
        unsigned :lcbPlcfpgp, 32, "1030 Count of bytes for the above data"
        unsigned :fcPlcfuim, 32, "1034 Offset in table stream of UIM property data This is intern[...]"
        unsigned :lcbPlcfium, 32, "1038 Count of bytes for the above data"
        unsigned :fcPlfguidUim, 32, "1042 Offset in table stream of UIM table of GUIDs This is inter[...]"
        unsigned :lcbPlfguidUim, 32, "1046 Count of bytes for the above data"
        unsigned :fcAtrdExtra, 32, "1050 Offset in table stream of plex of ATRDPost10 structures"
        unsigned :lcbAtrdExtra, 32, "1054 Count of bytes for the above data"
        unsigned :fcPlrsid, 32, "1058 Offset in table stream of RSID plex. This is undocumented [...]"
        unsigned :lcbPlrsid, 32, "1062 Count of bytes for the above data"
        unsigned :fcSttbfBkmkFactoid, 32, "1066 Offset in table stream of smart tag bookmark STTB This is [...]"
        unsigned :lcbSttbfBkmkFactoid, 32, "1070 Count of bytes for the above data"
        unsigned :fcPlcfBkfFactoid, 32, "1074 Offset in table stream of smart tag bookmark plc of cpFirs[...]"
        unsigned :lcbPlcfBkfFactoid, 32, "1078 Count of bytes for the above data"
        unsigned :fcPlcfcookie, 32, "1082 Offset in table stream of whether the NLCheck error handle[...]"
        unsigned :lcbPlcfcookie, 32, "1086 Count of bytes for the above data"
        unsigned :fcPlcfBklFactoid, 32, "1090 Offset in table stream of smart tag bookmark plc of cpLims[...]"
        unsigned :lcbPlcfBklFactoid, 32, "1094 Count of bytes for the above data"
        unsigned :fcFactoidData, 32, "1098 Offset in table stream of smart tag data This is undocumen[...]"
        unsigned :lcbFactoidData, 32, "1102 Count of bytes for the above data"
        unsigned :fcDocUndo, 32, "1106 Offset in table stream of undocumented undo / versioning d[...]"
        unsigned :lcbDocUndo, 32, "1110 Count of bytes for the above data"
        unsigned :fcSttbfBkmkFcc, 32, "1114 Offset in table stream of fcc bookmark sttb This is intern[...]"
        unsigned :lcbSttbfBkmkFcc, 32, "1118 Count of bytes for the above data"
        unsigned :fcPlcfBkfFcc, 32, "1122 Offset in table stream of fcc bookmark plc of cpFirsts Thi[...]"
        unsigned :lcbPlcfBkfFcc, 32, "1126 Count of bytes for the above data"
        unsigned :fcPlcfBklFcc, 32, "1130 Offset in table stream of fcc bookmark plc of cpLims This [...]"
        unsigned :lcbPlcfBklFcc, 32, "1134 Count of bytes for the above data"
        unsigned :fcSttbfbkmkBPRepairs, 32, "1138 Offset in table stream of file repair bookmark sttb This i[...]"
        unsigned :lcbSttbfbkmkBPRepairs, 32, "1142 Count of bytes for the above data"
        unsigned :fcPlcfbkfBPRepairs, 32, "1146 Offset in table stream of file repair bookmark plc of cpFi[...]"
        unsigned :lcbPlcfbkfBPRepairs, 32, "1150 Count of bytes for the above data"
        unsigned :fcPlcfbklBPRepairs, 32, "1154 Offset in table stream of file repair bookmark plc of cpLi[...]"
        unsigned :lcbPlcfbklBPRepairs, 32, "1158 Count of bytes for the above data"
        unsigned :fcPmsNew, 32, "1162 Offset in table stream of new mail merge state information[...]"
        unsigned :lcbPmsNew, 32, "1166 Count of bytes for the above data"
        unsigned :fcODSO, 32, "1170 Offset in table stream of IMsoODSO/IMsoMailmerge Informati[...]"
        unsigned :lcbODSO, 32, "1174 Count of bytes for the above data"
        unsigned :fcPlcfpmiOldXP, 32, "1178 Offset in table stream of Paragraph Mark Information (Old [...]"
        unsigned :lcbPlcfpmiOldXP, 32, "1182 Count of bytes for the above data ."
        unsigned :fcPlcfpmiNewXP, 32, "1186 Offset in table stream of Paragraph Mark Information (New [...]"
        unsigned :lcbPlcfpmiNewXP, 32, "1190 Count of bytes for the above data."
        unsigned :fcPlcfpmiMixedXP, 32, "1194 Offset in table stream of Paragraph Mark Information (Mixe[...]"
        unsigned :lcbPlcfpmiMixedXP, 32, "1198 Count of bytes for the above data."
        unsigned :fcEncryptedProps, 32, "1202 Offset in table stream of encryption properties This is an[...]"
        unsigned :lcbEncryptedProps, 32, "1206 Count of bytes for the above data"
        unsigned :fcPlcffactoid, 32, "1210 Offset in table stream of background factoid checking stat[...]"
        unsigned :lcbPlcffactoid, 32, "1214 Count of bytes for the above data."
        unsigned :fcPlcflvcOldXP, 32, "1218 Offset in table stream of LVC PLC (Old View) for Word 2002[...]"
        unsigned :lcbPlcflvcOldXP, 32, "1222 Count of bytes for the above data."
        unsigned :fcPlcflvcNewXP, 32, "1226 Offset in table stream of LVC PLC (New View) for Word 2002[...]"
        unsigned :lbcPlcflvcNewXP, 32, "1230 Count of bytes for the above data."
        unsigned :fcPlcflvcMixedXP, 32, "1234 Offset in table stream of LVC PLC (Mixed View) for Word 20[...]"
        unsigned :lcbPlcflvcMixedXP, 32, "1238 Count of bytes for the above data."
        unsigned :fcHplxsdr, 32, "1242 XML Schema Definition References"
        unsigned :lcbHplxsdr, 32, "1246 Count of bytes for the above data."
        unsigned :fcSttbfBkmkSdt, 32, "1250 SDT bookmark STTB"
        unsigned :lcbSttbfBkmkSdt, 32, "1254 Count of bytes for the above data."
        unsigned :fcPlcfBkfSdt, 32, "1258 SDT bookmark plc of cpFirsts"
        unsigned :lcbPlcfBkfSdt, 32, "1262 Count of bytes for the above data."
        unsigned :fcPlcfBklSdt, 32, "1266 SDT bookmark plc of cpLims"
        unsigned :lcbPlcfBklSdt, 32, "1270 Count of bytes for the above data."
        unsigned :fcCustomXForm, 32, "1274 Custom XML Transform on save"
        unsigned :lcbCustomXForm, 32, "1278 Count of bytes for the above data."
        unsigned :fcSttbfBkmkProt, 32, "1282 Range protection bookmark STTB This is undocumented bookma[...]"
        unsigned :lcbSttbfBkmkProt, 32, "1286 Count of bytes for the above data."
        unsigned :fcPlcfBkfProt, 32, "1290 Range protection bookmark plc of cpFirsts This is undocume[...]"
        unsigned :lcbPlcfBkfProt, 32, "1294 Count of bytes for the above data."
        unsigned :fcPlcfBklProt, 32, "1298 Range protection bookmark plc of cpLims This is undocument[...]"
        unsigned :lcbPlcfBklProt, 32, "1302 Count of bytes for the above data."
        unsigned :fcSttbProtUser, 32, "1306 Range protection user list STTB This is undocumented user [...]"
        unsigned :lcbSttbProtUser, 32, "1310 Count of bytes for the above data."
        unsigned :fcPlcftpc, 32, "1314 Current text paragraph cache This is unused."
        unsigned :lcbPlcftpc, 32, "1318 Count of bytes for the above data."
        unsigned :fcPlcfpmiOld, 32, "1322 Paragraph Mark Information (Old View) This is an internal [...]"
        unsigned :lcbPlcfpmiOld, 32, "1326 Count of bytes for the above data."
        unsigned :fcPlcfpmiOldInline, 32, "1330 Paragraph Mark Information (Old Inline View) This is an in[...]"
        unsigned :lcbPlcfpmiOldInline, 32, "1334 Count of bytes for the above data."
        unsigned :fcPlcfpmiNew, 32, "1338 Paragraph Mark Information (New View) This is an internal [...]"
        unsigned :lcbPlcfpmiNew, 32, "1342 Count of bytes for the above data."
        unsigned :fcPlcfpmiNewInline, 32, "1346 Paragraph Mark Information (New Inline View) This is an in[...]"
        unsigned :lcbPlcfpmiNewInline, 32, "1350 Count of bytes for the above data."
        unsigned :fcPlcflvcOld, 32, "1354 LVC PLC (Old View) This is an internal information cache u[...]"
        unsigned :lcbPlcflvcOld, 32, "1358 Count of bytes for the above data."
        unsigned :fcPlcflvcOldInline, 32, "1362 LVC PLC (Old Inline View) This is an internal information [...]"
        unsigned :lcbPlcflvcOldInline, 32, "1366 Count of bytes for the above data."
        unsigned :fcPlcflvcNew, 32, "1370 LVC PLC (New View) This is an internal information cache u[...]"
        unsigned :lcbPlcflvcNew, 32, "1374 Count of bytes for the above data."
        unsigned :fcPlcflvcNewInline, 32, "1378 LVC PLC (New Inline View) This is an internal information [...]"
        unsigned :lcbPlcflvcNewInline, 32, "1382 Count of bytes for the above data."
        unsigned :fcpgdMother, 192, "1386 This is an internal information cache used by Word."
        unsigned :fcpgdFtn, 192, "1410 This is an internal information cache used by Word."
        unsigned :fcpgdEdn, 192, "1434 This is an internal information cache used by Word."
        unsigned :fcAfd, 32, "1458 This is internal revision mark view information used by Wo[...]"
        unsigned :lcbAfd, 32, "1462 Count of bytes for the above data."
        unsigned :cswNew, 16, "1466 The number of entries in rgswNew[]"
        unsigned :nFib, 16, "1468 The actual nFib, moved here because some readers assumed t[...]"
        unsigned :cQuickSavesNew, 16, "1470 Because of the above, we need to use cQuickSaves [...]"
        group :ol, :fcStshfOrig, :lcbStshfOrig
        group :ol, :fcStshf, :lcbStshf
        group :ol, :fcPlcffndRef, :lcbPlcffndRef
        group :ol, :fcPlcffndTxt, :lcbPlcffndTxt
        group :ol, :fcPlcfandRef, :lcbPlcfandRef
        group :ol, :fcPlcfandTxt, :lcbPlcfandTxt
        group :ol, :fcPlcfsed, :lcbPlcfsed
        group :ol, :fcPlcpad, :lcbPlcpad
        group :ol, :fcPlcfphe, :lcbPlcfphe
        group :ol, :fcSttbfglsy, :lcbSttbfglsy
        group :ol, :fcPlcfglsy, :lcbPlcfglsy
        group :ol, :fcPlcfhdd, :lcbPlcfhdd
        group :ol, :fcPlcfbteChpx, :lcbPlcfbteChpx
        group :ol, :fcPlcfbtePapx, :lcbPlcfbtePapx
        group :ol, :fcPlcfsea, :lcbPlcfsea
        group :ol, :fcSttbfffn, :lcbSttbfffn
        group :ol, :fcPlcffldMom, :lcbPlcffldMom
        group :ol, :fcPlcffldHdr, :lcbPlcffldHdr
        group :ol, :fcPlcffldFtn, :lcbPlcffldFtn
        group :ol, :fcPlcffldAtn, :lcbPlcffldAtn
        group :ol, :fcPlcffldMcr, :lcbPlcffldMcr
        group :ol, :fcSttbfbkmk, :lcbSttbfbkmk
        group :ol, :fcPlcfbkf, :lcbPlcfbkf
        group :ol, :fcPlcfbkl, :lcbPlcfbkl
        group :ol, :fcCmds, :lcbCmds
        group :ol, :fcPlcmcr, :lcbPlcmcr
        group :ol, :fcSttbfmcr, :lcbSttbfmcr
        group :ol, :fcPrDrvr, :lcbPrDrvr
        group :ol, :fcPrEnvPort, :lcbPrEnvPort
        group :ol, :fcPrEnvLand, :lcbPrEnvLand
        group :ol, :fcWss, :lcbWss
        group :ol, :fcDop, :lcbDop
        group :ol, :fcSttbfAssoc, :lcbSttbfAssoc
        group :ol, :fcClx, :lcbClx
        group :ol, :fcPlcfpgdFtn, :lcbPlcfpgdFtn
        group :ol, :fcAutosaveSource, :lcbAutosaveSource
        group :ol, :fcGrpXstAtnOwners, :lcbGrpXstAtnOwners
        group :ol, :fcSttbfAtnbkmk, :lcbSttbfAtnbkmk
        group :ol, :fcPlcdoaMom, :lcbPlcdoaMom
        group :ol, :fcPlcdoaHdr, :lcbPlcdoaHdr
        group :ol, :fcPlcspaMom, :lcbPlcspaMom
        group :ol, :fcPlcspaHdr, :lcbPlcspaHdr
        group :ol, :fcPlcfAtnbkf, :lcbPlcfAtnbkf
        group :ol, :fcPlcfAtnbkl, :lcbPlcfAtnbkl
        group :ol, :fcPms, :lcbPms
        group :ol, :fcFormFldSttbs, :lcbFormFldSttbs
        group :ol, :fcPlcfendRef, :lcbPlcfendRef
        group :ol, :fcPlcfendTxt, :lcbPlcfendTxt
        group :ol, :fcPlcffldEdn, :lcbPlcffldEdn
        group :ol, :fcPlcfpgdEdn, :lcbPlcfpgdEdn
        group :ol, :fcDggInfo, :lcbDggInfo
        group :ol, :fcSttbfRMark, :lcbSttbfRMark
        group :ol, :fcSttbCaption, :lcbSttbCaption
        group :ol, :fcSttbAutoCaption, :lcbSttbAutoCaption
        group :ol, :fcPlcfwkb, :lcbPlcfwkb
        group :ol, :fcPlcfspl, :lcbPlcfspl
        group :ol, :fcPlcftxbxTxt, :lcbPlcftxbxTxt
        group :ol, :fcPlcffldTxbx, :lcbPlcffldTxbx
        group :ol, :fcPlcfhdrtxbxTxt, :lcbPlcfhdrtxbxTxt
        group :ol, :fcPlcffldHdrTxbx, :lcbPlcffldHdrTxbx
        group :ol, :fcStwUser, :lcbStwUser
        group :ol, :fcCookieData, :lcbCookieData
        group :ol, :fcSttbfIntlFld, :lcbSttbfIntlFld
        group :ol, :fcRouteSlip, :lcbRouteSlip
        group :ol, :fcSttbSavedBy, :lcbSttbSavedBy
        group :ol, :fcSttbFnm, :lcbSttbFnm
        group :ol, :fcPlcfLst, :lcbPlcfLst
        group :ol, :fcPlfLfo, :lcbPlfLfo
        group :ol, :fcPlcftxbxBkd, :lcbPlcftxbxBkd
        group :ol, :fcPlcftxbxHdrBkd, :lcbPlcftxbxHdrBkd
        group :ol, :fcDocUndoWord9, :lcbDocUndoWord9
        group :ol, :fcRgbuse, :lcbRgbuse
        group :ol, :fcUsp, :lcbUsp
        group :ol, :fcUskf, :lcbUskf
        group :ol, :fcPlcupcRgbuse, :lcbPlcupcRgbuse
        group :ol, :fcPlcupcUsp, :lcbPlcupcUsp
        group :ol, :fcSttbGlsyStyle, :lcbSttbGlsyStyle
        group :ol, :fcPlgosl, :lcbPlgosl
        group :ol, :fcPlcocx, :lcbPlcocx
        group :ol, :fcPlcfbteLvc, :lcbPlcfbteLvc
        group :ol, :fcPlcflvcPre10, :lcbPlcflvcPre10
        group :ol, :fcPlcasumy, :lcbPlcasumy
        group :ol, :fcPlcfgram, :lcbPlcfgram
        group :ol, :fcSttbListNames, :lcbSttbListNames
        group :ol, :fcSttbfUssr, :lcbSttbfUssr
        group :ol, :fcPlcfTch, :lcbPlcfTch
        group :ol, :fcRmdfThreading, :lcbRmdfThreading
        group :ol, :fcMid, :lcbMid
        group :ol, :fcSttbRgtplc, :lcbSttbRgtplc
        group :ol, :fcMsoEnvelope, :lcbMsoEnvelope
        group :ol, :fcPlcflad, :lcbPlcflad
        group :ol, :fcRgdofr, :lcbRgdofr
        group :ol, :fcPlcosl, :lcbPlcosl
        group :ol, :fcPlcfcookieOld, :lcbPlcfcookieOld
        group :ol, :fcUnused, :lcbUnused
        group :ol, :fcPlcfpgp, :lcbPlcfpgp
        group :ol, :fcPlcfuim, :lcbPlcfium
        group :ol, :fcPlfguidUim, :lcbPlfguidUim
        group :ol, :fcAtrdExtra, :lcbAtrdExtra
        group :ol, :fcPlrsid, :lcbPlrsid
        group :ol, :fcSttbfBkmkFactoid, :lcbSttbfBkmkFactoid
        group :ol, :fcPlcfBkfFactoid, :lcbPlcfBkfFactoid
        group :ol, :fcPlcfcookie, :lcbPlcfcookie
        group :ol, :fcPlcfBklFactoid, :lcbPlcfBklFactoid
        group :ol, :fcFactoidData, :lcbFactoidData
        group :ol, :fcDocUndo, :lcbDocUndo
        group :ol, :fcSttbfBkmkFcc, :lcbSttbfBkmkFcc
        group :ol, :fcPlcfBkfFcc, :lcbPlcfBkfFcc
        group :ol, :fcPlcfBklFcc, :lcbPlcfBklFcc
        group :ol, :fcSttbfbkmkBPRepairs, :lcbSttbfbkmkBPRepairs
        group :ol, :fcPlcfbkfBPRepairs, :lcbPlcfbkfBPRepairs
        group :ol, :fcPlcfbklBPRepairs, :lcbPlcfbklBPRepairs
        group :ol, :fcPmsNew, :lcbPmsNew
        group :ol, :fcODSO, :lcbODSO
        group :ol, :fcPlcfpmiOldXP, :lcbPlcfpmiOldXP
        group :ol, :fcPlcfpmiNewXP, :lcbPlcfpmiNewXP
        group :ol, :fcPlcfpmiMixedXP, :lcbPlcfpmiMixedXP
        group :ol, :fcEncryptedProps, :lcbEncryptedProps
        group :ol, :fcPlcffactoid, :lcbPlcffactoid
        group :ol, :fcPlcflvcOldXP, :lcbPlcflvcOldXP
        group :ol, :fcPlcflvcMixedXP, :lcbPlcflvcMixedXP
        group :ol, :fcHplxsdr, :lcbHplxsdr;
        group :ol, :fcSttbfBkmkSdt, :lcbSttbfBkmkSdt
        group :ol, :fcPlcfBkfSdt, :lcbPlcfBkfSdt
        group :ol, :fcPlcfBklSdt, :lcbPlcfBklSdt
        group :ol, :fcCustomXForm, :lcbCustomXForm
        group :ol, :fcSttbfBkmkProt, :lcbSttbfBkmkProt
        group :ol, :fcPlcfBkfProt, :lcbPlcfBkfProt
        group :ol, :fcPlcfBklProt, :lcbPlcfBklProt
        group :ol, :fcSttbProtUser, :lcbSttbProtUser
        group :ol, :fcPlcftpc, :lcbPlcftpc
        group :ol, :fcPlcfpmiOld, :lcbPlcfpmiOld
        group :ol, :fcPlcfpmiOldInline, :lcbPlcfpmiOldInline
        group :ol, :fcPlcfpmiNew, :lcbPlcfpmiNew
        group :ol, :fcPlcfpmiNewInline, :lcbPlcfpmiNewInline
        group :ol, :fcPlcflvcOld, :lcbPlcflvcOld
        group :ol, :fcPlcflvcOldInline, :lcbPlcflvcOldInline
        group :ol, :fcPlcflvcNew, :lcbPlcflvcNew
        group :ol, :fcPlcflvcNewInline, :lcbPlcflvcNewInline
        group :ol, :fcAfd, :lcbAfd
        endianness "intel"
    end

end #WordStructures
