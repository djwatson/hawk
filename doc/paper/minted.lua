function CodeBlock(elem)
  local lang = elem.classes[1]
  if not lang or lang == '' then
    return elem
  end
  opts = 'fontsize=\\footnotesize,tabsize=2,breaklines=false,autogobble=true'
  return pandoc.RawBlock(
    'latex',
    '\\vspace{0.5\\baselineskip}\n'
    .. '\\begin{minipage}{\\linewidth}\n'
    .. '\\begin{minted}[' .. opts .. ']{' .. lang .. '}\n'
    .. elem.text .. '\n\\end{minted}\n'
    .. '\\end{minipage}\n'
    .. '\\vspace{0.5\\baselineskip}'
  )
end
